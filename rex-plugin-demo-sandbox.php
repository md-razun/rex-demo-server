<?php
/**
 * Plugin Name: Rex Multisite Demo
 * Description: Creates per-user demo sites with 30-min expiry and auto-login.
 * Version: 1.0.2
 * Author: RexTheme
 */

if (!defined('ABSPATH')) exit;

class Rex_Multisite_Demo {

    private $base_sites = [
            'wpvr' => 1,     // Site ID of wpvr-base
            'plugin2' => 3,
            'plugin3' => 4,
    ];

    public function __construct() {
        // Shortcode
        add_shortcode('watch_demo', [$this, 'watch_demo_shortcode']);

        // AJAX for creating demo site
        add_action('wp_ajax_rex_create_demo_site', [$this, 'create_demo_site']);
        add_action('wp_ajax_nopriv_rex_create_demo_site', [$this, 'create_demo_site']);

        // Cleanup expired demo sites
        add_action('rex_demo_cleanup', [$this, 'cleanup_expired_sites']);
        if (!wp_next_scheduled('rex_demo_cleanup')) {
            wp_schedule_event(time(), 'five_minutes', 'rex_demo_cleanup');
        }
        add_filter('cron_schedules', function ($schedules) {
            $schedules['five_minutes'] = ['interval' => 300, 'display' => 'Every 5 Minutes'];
            return $schedules;
        });

        // Auto-login for demo token
        add_action('init', [$this, 'handle_demo_token']);

        // Countdown timer in footer - higher priority (1) to ensure it runs
        add_action('wp_footer', [$this, 'demo_countdown_script'], 1);
        // Also add countdown timer to admin footer for admin pages
        add_action('admin_footer', [$this, 'demo_countdown_script'], 1);
        add_action('admin_print_footer_scripts', [$this, 'demo_countdown_script'], 1);


        // Hook early to check for demo user and ensure timer will be displayed
        add_action('init', [$this, 'check_demo_user'], 5);

        add_action('wp_enqueue_scripts', function() {
            wp_enqueue_script('rex-demo-js', plugin_dir_url(__FILE__) . 'js/demo-script.js', ['jquery'], '1.0.2', true);

            // Pass AJAX URL and nonce to JS
            wp_localize_script('rex-demo-js', 'rex_demo_ajax', [
                    'ajax_url' => admin_url('admin-ajax.php'),
                    'nonce'    => wp_create_nonce('rex_demo_nonce')
            ]);
        });


    }

    /** Shortcode [watch_demo plugin="wpvr" button_name="Watch Demo"] */
    public function watch_demo_shortcode($atts) {
        $atts = shortcode_atts([
                'plugin' => 'wpvr',
                'button_name' => 'Watch Demo'
        ], $atts, 'watch_demo');

        if (!$atts['plugin'] || !isset($this->base_sites[$atts['plugin']])) return '';

        $id = 'rex-demo-btn-' . uniqid();
        ob_start(); ?>
        <button id="<?php echo $id; ?>" class="rex-watch-demo-btn" data-plugin="<?php echo esc_attr($atts['plugin']); ?>">
            <?php echo esc_html($atts['button_name']); ?>
        </button>
        <script>
            jQuery(document).ready(function($){
                $('#<?php echo $id; ?>').click(function(e){
                    e.preventDefault();
                    var button = $(this);
                    var plugin = button.data('plugin');
                    button.prop('disabled', true).text('Creating demo...');
                    $.post('<?php echo admin_url("admin-ajax.php"); ?>', {
                        action: 'rex_create_demo_site',
                        plugin: plugin,
                        security: '<?php echo wp_create_nonce("rex_demo_nonce"); ?>'
                    }, function(res){
                        if(res.success && res.data.url){
                            window.location.href = res.data.url;
                        } else {
                            alert(res.data || 'Error creating demo');
                            button.prop('disabled', false).text('<?php echo esc_js($atts['button_name']); ?>');
                        }
                    });
                });
            });
        </script>
        <?php
        return ob_get_clean();
    }

    /** AJAX: Create demo site with improved database initialization */
    public function create_demo_site() {
        if (!isset($_POST['security']) || !wp_verify_nonce($_POST['security'], 'rex_demo_nonce')) {
            wp_send_json_error('Security check failed');
            return;
        }

        $plugin = sanitize_text_field($_POST['plugin'] ?? '');
        if (!$plugin || !isset($this->base_sites[$plugin])) {
            wp_send_json_error('Invalid plugin');
            return;
        }

        // Get the base site ID
        $base_id = $this->base_sites[$plugin];

        // Generate a unique ID for the new site
        $user_key = substr(uniqid(), -6);

        // Get current network details
        $current_site = get_current_site();
        $network_domain = $current_site->domain;

        // Create a subdomain with a simple structure
        $subdomain = $plugin . "-" . $user_key;
        $domain = $subdomain . "." . $network_domain;

        // Log detailed info for debugging
        error_log("Demo site creation attempt: $domain (base site ID: $base_id)");
        error_log("Network domain: $network_domain");
        error_log("Current site ID: " . get_current_blog_id());

        try {
            global $wpdb;

            // Check if the domain already exists
            if (domain_exists($domain, '/', null)) {
                wp_send_json_error('This domain already exists');
                return;
            }

            // Ensure required files are loaded
            require_once(ABSPATH . 'wp-admin/includes/ms.php');
            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

            // Force registration to be enabled temporarily
            add_filter('pre_site_option_registration', function() { return 'all'; }, 9999);
            add_filter('pre_site_option_add_new_users', function() { return 1; }, 9999);

            error_log("Starting site creation for domain: $domain");

            // Create the blog using built-in function
            $blog_id = wpmu_create_blog(
                $domain,
                '/',
                ucfirst($plugin) . ' Demo - ' . $user_key,
                get_current_user_id() ?: 1,
                ['public' => 1],
                $current_site->id
            );

            if (is_wp_error($blog_id)) {
                error_log("wpmu_create_blog error: " . $blog_id->get_error_message());
                throw new Exception("Site creation failed: " . $blog_id->get_error_message());
            }

            if (empty($blog_id)) {
                error_log("wpmu_create_blog returned empty blog_id");
                throw new Exception("Site creation failed: No blog ID returned");
            }

            error_log("Blog created with ID: $blog_id");

            // Verify that the tables exist before proceeding
            $table_prefix = $wpdb->get_blog_prefix($blog_id);
            $options_table = $table_prefix . 'options';

            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$options_table'");
            if (!$table_exists) {
                error_log("Table $options_table doesn't exist after creation");

                // Try to fix by manually running populate_blog
                error_log("Attempting to manually populate blog tables");

                // Set up globals needed for populate_blog
                $title = ucfirst($plugin) . ' Demo - ' . $user_key;
                $site_user = get_user_by('id', get_current_user_id() ?: 1);
                $email = $site_user ? $site_user->user_email : 'demo@example.com';

                // Call the function directly
                if (function_exists('populate_blog')) {
                    $populate_result = populate_blog($blog_id, $title, $email);
                    error_log("populate_blog result: " . ($populate_result ? "Success" : "Failed"));
                } else {
                    error_log("populate_blog function not available");
                }

                // Check again if tables exist
                $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$options_table'");
                if (!$table_exists) {
                    throw new Exception("Failed to create required database tables");
                }
            }

            // Populate the site with basic options using our custom method
            $this->populate_basic_options($blog_id, $plugin, $user_key, $domain);

            // Configure basic site settings
            switch_to_blog($blog_id);

            update_option('siteurl', 'http://' . $domain);
            update_option('home', 'http://' . $domain);
            update_option('blogname', ucfirst($plugin) . ' Demo - ' . $user_key);
            update_option('admin_email', 'demo@' . $domain);
            update_option('_demo_expiry', time() + 1800); // 30 minutes

            restore_current_blog();

            // Copy content from the base site
            $this->copy_site_content($base_id, $blog_id, $plugin, $user_key, $domain);

            // Create demo user with admin privileges
            $demo_url = $this->create_demo_user($blog_id, $user_key, $domain);

            error_log("Demo site successfully created: $domain (ID: $blog_id)");

            // Return success response
            wp_send_json_success([
                'url' => $demo_url,
                'site_id' => $blog_id,
                'domain' => $domain,
                'expires' => date('Y-m-d H:i:s', time() + 1800)
            ]);

        } catch (Exception $e) {
            error_log("Demo site creation failed: " . $e->getMessage());
            wp_send_json_error('Error creating demo site: ' . $e->getMessage());
        }
    }

    /**
     * Populate basic options for a new site
     */
    private function populate_basic_options($blog_id, $plugin, $user_key, $domain) {
        global $wpdb;

        error_log("Populating basic options for blog ID: $blog_id");

        $table_name = $wpdb->base_prefix . $blog_id . '_options';

        // Check if the table exists before trying to insert
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");
        if (!$table_exists) {
            throw new Exception("Table $table_name doesn't exist. Cannot populate options.");
        }

        // List of basic options needed for a WordPress site to function
        $basic_options = [
            ['siteurl', 'http://' . $domain, 'yes'],
            ['home', 'http://' . $domain, 'yes'],
            ['blogname', ucfirst($plugin) . ' Demo - ' . $user_key, 'yes'],
            ['admin_email', 'demo@' . $domain, 'yes'],
            ['users_can_register', '0', 'yes'],
            ['_demo_expiry', time() + 1800, 'no'],
            ['blog_public', '1', 'yes'],
            ['blogdescription', 'Demo site for ' . ucfirst($plugin), 'yes'],
            ['timezone_string', 'UTC', 'yes'],
            ['template', 'twentytwentythree', 'yes'], // Default theme
            ['stylesheet', 'twentytwentythree', 'yes'] // Default theme
        ];

        // Directly insert required options
        foreach ($basic_options as $option) {
            list($name, $value, $autoload) = $option;

            // Use direct SQL to avoid WordPress hooks
            $wpdb->query($wpdb->prepare(
                "INSERT INTO $table_name (`option_name`, `option_value`, `autoload`) 
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE `option_value` = VALUES(`option_value`)",
                $name, $value, $autoload
            ));

            if ($wpdb->last_error) {
                error_log("Error setting option $name: " . $wpdb->last_error);
            }
        }

        error_log("Basic options populated for blog ID: $blog_id");
    }

    /** Copy content from base site to new demo site */
    private function copy_site_content($base_id, $new_site_id, $plugin, $user_key, $subdomain) {
        // Copy options from base site
        switch_to_blog($base_id);
        $options = wp_load_alloptions();

        // Filter out options that shouldn't be copied
        $skip_options = [
                'siteurl', 'home', 'blogname', 'admin_email',
                'users_can_register', 'default_role', '_demo_expiry',
                'upload_path', 'upload_url_path',
                'recently_activated', 'active_plugins', 'deactivated_plugins', // Skip plugin activation related options
                'wp_user_roles' // Skip roles which we'll initialize properly later
        ];

        foreach ($skip_options as $skip) {
            unset($options[$skip]);
        }
        restore_current_blog();

        // Switch to new site and set options
        switch_to_blog($new_site_id);

        // Set basic site options
        update_option('siteurl', 'http://' . $subdomain);
        update_option('home', 'http://' . $subdomain);
        update_option('blogname', ucfirst($plugin) . ' Demo - ' . $user_key);
        update_option('admin_email', 'demo@' . $subdomain);

        // Ensure plugin-related options are properly set as arrays
        update_option('active_plugins', array());
        update_option('deactivated_plugins', array());
        update_option('recently_activated', array());

        // Initialize WordPress roles properly to prevent corruption
        $this->initialize_wp_roles($new_site_id);

        // Copy filtered options
        foreach ($options as $k => $v) {
            if (!in_array($k, $skip_options)) {
                update_option($k, $v);
            }
        }

        // Set expiry timestamp
        $expiry = time() + 1800; // 30 mins
        update_option('_demo_expiry', $expiry);

        // Copy posts and pages from base site
        $this->copy_posts($base_id, $new_site_id);

        restore_current_blog();
    }

    /** Copy posts from base site to new site */
    private function copy_posts($base_id, $new_site_id) {
        switch_to_blog($base_id);

        $posts = get_posts([
                'numberposts' => -1,
                'post_type' => 'any',
                'post_status' => 'any'
        ]);

        $post_data = [];
        foreach ($posts as $post) {
            $post_data[] = [
                    'post_title' => $post->post_title,
                    'post_content' => $post->post_content,
                    'post_excerpt' => $post->post_excerpt,
                    'post_status' => $post->post_status,
                    'post_type' => $post->post_type,
                    'post_date' => $post->post_date,
                    'post_date_gmt' => $post->post_date_gmt,
                    'post_modified' => $post->post_modified,
                    'post_modified_gmt' => $post->post_modified_gmt,
                    'menu_order' => $post->menu_order,
                    'post_name' => $post->post_name,
                    'meta' => get_post_meta($post->ID)
            ];
        }

        restore_current_blog();

        // Insert posts into new site
        switch_to_blog($new_site_id);

        foreach ($post_data as $post_info) {
            $meta = $post_info['meta'];
            unset($post_info['meta']);

            $new_post_id = wp_insert_post($post_info);

            if ($new_post_id && !is_wp_error($new_post_id)) {
                // Copy post meta
                foreach ($meta as $key => $values) {
                    foreach ($values as $value) {
                        add_post_meta($new_post_id, $key, maybe_unserialize($value));
                    }
                }
            }
        }

        restore_current_blog();
    }

    /** Create demo user and return login URL */
    private function create_demo_user($new_site_id, $user_key, $subdomain) {
        switch_to_blog($new_site_id);

        $guest_username = 'demo_admin_' . $user_key;
        $guest_email = $guest_username . '@demo.local';
        $guest_password = wp_generate_password(12, true);
        $expiry = time() + 1800;

        $user_id = wp_create_user($guest_username, $guest_password, $guest_email);

        if (!is_wp_error($user_id)) {
            $user = new WP_User($user_id);
            $user->set_role('administrator');
            update_user_meta($user_id, '_demo_expiry', $expiry);

            // Ensure user is added to this site
            add_user_to_blog($new_site_id, $user_id, 'administrator');

            // Generate secure token for auto-login
            $token_data = [
                    'user_id' => $user_id,
                    'site_id' => $new_site_id,
                    'expiry' => $expiry,
                    'created' => time(),
                    'hash' => wp_hash($user_id . $new_site_id . $expiry)
            ];

            $token = base64_encode(json_encode($token_data));

            // Store token temporarily (5 minutes to use)
            set_transient('demo_token_' . md5($token), $token_data, 300);

            $demo_url = 'http://' . $subdomain . '/?demo_login=' . urlencode($token);
        } else {
            error_log('Demo user creation failed: ' . $user_id->get_error_message());
            $demo_url = 'http://' . $subdomain;
        }

        restore_current_blog();
        return $demo_url;
    }

    /** Handle guest token login */
    public function handle_demo_token() {
        if (!isset($_GET['demo_login'])) return;

        $token = sanitize_text_field($_GET['demo_login']);

        try {
            $token_data = json_decode(base64_decode($token), true);

            if (!$token_data || !isset($token_data['user_id']) || !isset($token_data['site_id'])) {
                return;
            }

            // Check if token exists and is valid
            $stored_data = get_transient('demo_token_' . md5($token));
            if (!$stored_data || $stored_data['expiry'] < time()) {
                wp_die('Demo session has expired or is invalid.');
                return;
            }

            // Verify token hash
            if (!isset($token_data['hash']) || $token_data['hash'] !== wp_hash($token_data['user_id'] . $token_data['site_id'] . $token_data['expiry'])) {
                wp_die('Invalid demo token.');
                return;
            }

            $user_id = (int)$token_data['user_id'];
            $site_id = (int)$token_data['site_id'];

            // Verify we're on the correct site
            if (get_current_blog_id() !== $site_id) {
                wp_die('Invalid demo site access.');
                return;
            }

            $user = get_user_by('id', $user_id);
            if (!$user) {
                wp_die('Demo user not found.');
                return;
            }

            // Check if user belongs to this site
            if (!is_user_member_of_blog($user_id, $site_id)) {
                add_user_to_blog($site_id, $user_id, 'administrator');
            }

            // Auto-login the user
            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id, true);
            do_action('wp_login', $user->user_login, $user);

            // Delete the token after use
            delete_transient('demo_token_' . md5($token));

            // Redirect to admin dashboard
            wp_redirect(admin_url());
            exit;

        } catch (Exception $e) {
            error_log('Demo token error: ' . $e->getMessage());
            wp_die('Invalid demo token.');
        }
    }

    /** Cleanup expired demo sites */
    public function cleanup_expired_sites() {
        $sites = get_sites(['number' => 0]);
        foreach ($sites as $site) {
            $expiry = get_blog_option($site->blog_id, '_demo_expiry');
            if ($expiry && $expiry < time()) {
                require_once ABSPATH . 'wp-admin/includes/ms.php';

                // Delete all users from this demo site first
                $site_users = get_users(['blog_id' => $site->blog_id]);
                foreach ($site_users as $user) {
                    $demo_expiry = get_user_meta($user->ID, '_demo_expiry', true);
                    if ($demo_expiry) {
                        wp_delete_user($user->ID);
                    }
                }

                wp_delete_site($site->blog_id);
                error_log("Deleted expired demo site: {$site->domain} (ID: {$site->blog_id})");
            }
        }
    }

    /** Countdown timer */
    public function demo_countdown_script() {
        error_log('Demo countdown script');
        if (!is_user_logged_in()) return;
        error_log('Demo countdown script 2');
        error_log('Current user id: ' . get_current_user_id());
//        $expiry = get_user_meta(get_current_user_id(), '_demo_expiry', true);
        $expiry =   get_user_meta('2', '_demo_expiry', true);
        error_log('Demo expiry: ' . print_r($expiry, true));
        if (!$expiry) return;

        $remaining = $expiry - time();
        if ($remaining <= 0) {
            // Log out expired user
            wp_logout();
            wp_redirect(network_home_url());
            exit;
        }
        error_log(print_r($expiry, true));
        ?>
        <div id="rex-demo-timer" style="position:fixed;bottom:10px;right:10px;background:#222;color:#fff;padding:10px;border-radius:5px;z-index:9999;font-family:sans-serif;font-size:14px;">
            Demo Access: <span id="rex-demo-countdown"></span>
        </div>
        <script>
            var remaining = <?php echo intval($remaining); ?>;
            function updateCountdown(){
                var min = Math.floor(remaining / 60);
                var sec = remaining % 60;
                if (sec < 10) sec = '0' + sec;
                document.getElementById('rex-demo-countdown').innerText = min + 'm ' + sec + 's';
                remaining--;
                if(remaining < 0) {
                    alert('Demo session expired. You will be redirected to the main site.');
                    location.href = '<?php echo network_home_url(); ?>';
                }
            }
            updateCountdown();
            setInterval(updateCountdown, 1000);
        </script>
        <?php
    }

    /**
     * Check for demo user early in the loading process
     * This helps ensure the countdown timer will be properly displayed and fixes dashboard issues
     */
    public function check_demo_user() {
        error_log('Checking for demo user');
        if (is_user_logged_in()) {
            $user_id = get_current_user_id();
            $expiry = get_user_meta($user_id, '_demo_expiry', true);

            if ($expiry) {
                // Store in a transient for quick access
                set_transient('rex_demo_user_' . $user_id, $expiry, 1800);

                // Log for debugging
                error_log("Demo user detected: $user_id with expiry: " . date('Y-m-d H:i:s', $expiry));

                // Fix plugin-related options that could cause dashboard errors
                $this->fix_option_formats();

                // Fix plugin-related errors with high priority filters
                // Return empty arrays for problematic options
                add_filter('pre_option_recently_activated', function() { return array(); }, 999);
                add_filter('pre_option_deactivated_plugins', function() { return array(); }, 999);
                add_filter('pre_option_active_plugins', function() { return array(); }, 999);

                // Additional protection for plugin data that might be accessed by the dashboard
                add_filter('pre_site_option_deactivate_plugins', function() { return array(); }, 999);
                add_filter('pre_site_option_active_sitewide_plugins', function() { return array(); }, 999);
                add_filter('pre_site_transient_update_plugins', function() { return (object) ['response' => array()]; }, 999);

                // Prevent trying to load non-existent plugins that might be in the database
                add_filter('option_active_plugins', function($plugins) {
                    if (!is_array($plugins)) return array();
                    return array_filter($plugins, 'file_exists');
                }, 999);

                // Suppress plugin update checks entirely
                remove_action('load-update-core.php', 'wp_update_plugins');
                add_filter('pre_set_site_transient_update_plugins', function($value) {
                    return (object) ['response' => array()];
                }, 999);

                // Disable admin notices related to plugins
                if (is_admin()) {
                    // Remove default notices that might cause errors
                    remove_all_actions('admin_notices');
                    remove_all_actions('network_admin_notices');
                    remove_all_actions('all_admin_notices');
                    remove_all_actions('user_admin_notices');

                    // Add only our own demo-related notice with high priority
                    add_action('admin_notices', function() {
                        echo '<div class="notice notice-info"><p>You are viewing a demo site. This demo will expire in ' .
                             ceil((get_user_meta(get_current_user_id(), '_demo_expiry', true) - time()) / 60) .
                             ' minutes.</p></div>';
                    }, 9999);
                }

                // If expired, log them out immediately
                if ($expiry < time()) {
                    wp_logout();
                    wp_redirect(network_home_url());
                    exit;
                }

                // Ensure we have the script in admin too
                add_action('admin_enqueue_scripts', function() {
                    wp_enqueue_script('jquery');
                });

                // Fix dashboard widgets that might cause issues
                add_action('wp_dashboard_setup', function() {
                    remove_meta_box('dashboard_activity', 'dashboard', 'normal');
                    remove_meta_box('dashboard_primary', 'dashboard', 'side');
                    remove_meta_box('dashboard_plugins', 'dashboard', 'normal');
                    remove_meta_box('dashboard_site_health', 'dashboard', 'normal');
                }, 9999);

                // Prevent site health checks which can cause errors
                add_filter('site_status_tests', function() { return array(); }, 9999);
            }
        }
    }

    /**
     * Properly initialize WordPress roles for a new site
     * This prevents the "array_keys(): Argument #1 ($array) must be of type array" error
     */
    private function initialize_wp_roles($blog_id) {
        global $wpdb;

        error_log("Initializing roles for blog ID: $blog_id");

        // Define default WordPress roles
        $default_roles = [
            'administrator' => [
                'name' => 'Administrator',
                'capabilities' => [
                    'switch_themes' => true,
                    'edit_themes' => true,
                    'activate_plugins' => true,
                    'edit_plugins' => true,
                    'edit_users' => true,
                    'edit_files' => true,
                    'manage_options' => true,
                    'moderate_comments' => true,
                    'manage_categories' => true,
                    'manage_links' => true,
                    'upload_files' => true,
                    'import' => true,
                    'unfiltered_html' => true,
                    'edit_posts' => true,
                    'edit_others_posts' => true,
                    'edit_published_posts' => true,
                    'publish_posts' => true,
                    'edit_pages' => true,
                    'read' => true,
                    'level_10' => true,
                    'level_9' => true,
                    'level_8' => true,
                    'level_7' => true,
                    'level_6' => true,
                    'level_5' => true,
                    'level_4' => true,
                    'level_3' => true,
                    'level_2' => true,
                    'level_1' => true,
                    'level_0' => true,
                    'edit_others_pages' => true,
                    'edit_published_pages' => true,
                    'publish_pages' => true,
                    'delete_pages' => true,
                    'delete_others_pages' => true,
                    'delete_published_pages' => true,
                    'delete_posts' => true,
                    'delete_others_posts' => true,
                    'delete_published_posts' => true,
                    'delete_private_posts' => true,
                    'edit_private_posts' => true,
                    'read_private_posts' => true,
                    'delete_private_pages' => true,
                    'edit_private_pages' => true,
                    'read_private_pages' => true,
                    'delete_users' => true,
                    'create_users' => true,
                    'unfiltered_upload' => true,
                    'edit_dashboard' => true,
                    'update_plugins' => true,
                    'delete_plugins' => true,
                    'install_plugins' => true,
                    'update_themes' => true,
                    'install_themes' => true,
                    'update_core' => true,
                    'list_users' => true,
                    'remove_users' => true,
                    'promote_users' => true,
                    'edit_theme_options' => true,
                    'delete_themes' => true,
                    'export' => true,
                ]
            ],
            'editor' => [
                'name' => 'Editor',
                'capabilities' => [
                    'moderate_comments' => true,
                    'manage_categories' => true,
                    'manage_links' => true,
                    'upload_files' => true,
                    'unfiltered_html' => true,
                    'edit_posts' => true,
                    'edit_others_posts' => true,
                    'edit_published_posts' => true,
                    'publish_posts' => true,
                    'edit_pages' => true,
                    'read' => true,
                    'level_7' => true,
                    'level_6' => true,
                    'level_5' => true,
                    'level_4' => true,
                    'level_3' => true,
                    'level_2' => true,
                    'level_1' => true,
                    'level_0' => true,
                    'edit_others_pages' => true,
                    'edit_published_pages' => true,
                    'publish_pages' => true,
                    'delete_pages' => true,
                    'delete_others_pages' => true,
                    'delete_published_pages' => true,
                    'delete_posts' => true,
                    'delete_others_posts' => true,
                    'delete_published_posts' => true,
                    'delete_private_posts' => true,
                    'edit_private_posts' => true,
                    'read_private_posts' => true,
                    'delete_private_pages' => true,
                    'edit_private_pages' => true,
                    'read_private_pages' => true,
                ]
            ],
            'author' => [
                'name' => 'Author',
                'capabilities' => [
                    'upload_files' => true,
                    'edit_posts' => true,
                    'edit_published_posts' => true,
                    'publish_posts' => true,
                    'read' => true,
                    'level_2' => true,
                    'level_1' => true,
                    'level_0' => true,
                    'delete_posts' => true,
                    'delete_published_posts' => true,
                ]
            ],
            'contributor' => [
                'name' => 'Contributor',
                'capabilities' => [
                    'edit_posts' => true,
                    'read' => true,
                    'level_1' => true,
                    'level_0' => true,
                    'delete_posts' => true,
                ]
            ],
            'subscriber' => [
                'name' => 'Subscriber',
                'capabilities' => [
                    'read' => true,
                    'level_0' => true,
                ]
            ]
        ];

        switch_to_blog($blog_id);

        // First, try through WordPress functions
        $serialized_roles = serialize($default_roles);
        update_option('wp_user_roles', $default_roles);

        // Double-check the option was saved correctly
        $saved_roles = get_option('wp_user_roles');

        // If still not an array or properly saved, use direct database queries
        if (!is_array($saved_roles)) {
            error_log("Roles not properly saved as array, trying direct database update");

            $table_name = $wpdb->prefix . 'options';

            // First check if the option exists
            $option_exists = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $table_name WHERE option_name = %s",
                    'wp_user_roles'
                )
            );

            if ($option_exists) {
                // Update existing option
                $wpdb->query(
                    $wpdb->prepare(
                        "UPDATE $table_name SET option_value = %s WHERE option_name = %s",
                        $serialized_roles,
                        'wp_user_roles'
                    )
                );
            } else {
                // Insert new option
                $wpdb->query(
                    $wpdb->prepare(
                        "INSERT INTO $table_name (option_name, option_value, autoload) VALUES (%s, %s, %s)",
                        'wp_user_roles',
                        $serialized_roles,
                        'yes'
                    )
                );
            }

            if ($wpdb->last_error) {
                error_log("Error updating wp_user_roles: " . $wpdb->last_error);
            } else {
                error_log("Directly updated wp_user_roles in the database");

                // Clear caches to ensure fresh data
                wp_cache_delete('alloptions', 'options');
                wp_cache_delete('notoptions', 'options');
                wp_cache_delete('wp_user_roles', 'options');

                // Verify once more
                $final_roles = get_option('wp_user_roles');
                if (!is_array($final_roles)) {
                    error_log("CRITICAL: Still unable to set roles as array. Trying last resort method.");

                    // Last resort: Delete and recreate
                    $wpdb->query(
                        $wpdb->prepare(
                            "DELETE FROM $table_name WHERE option_name = %s",
                            'wp_user_roles'
                        )
                    );

                    $wpdb->query(
                        $wpdb->prepare(
                            "INSERT INTO $table_name (option_name, option_value, autoload) VALUES (%s, %s, %s)",
                            'wp_user_roles',
                            $serialized_roles,
                            'yes'
                        )
                    );

                    wp_cache_flush();
                }
            }
        } else {
            error_log("Successfully initialized roles for blog ID: $blog_id as an array");
        }

        // Initialize other critical array options that could be corrupted
        $this->initialize_array_option('active_plugins', array());
        $this->initialize_array_option('deactivated_plugins', array());
        $this->initialize_array_option('recently_activated', array());

        restore_current_blog();
    }

    /**
     * Helper method to ensure options that should be arrays are properly initialized as arrays
     * This prevents errors like "array_merge(): Argument #1 must be of type array, string given"
     *
     * @param string $option_name The option name to initialize
     * @param array $default_value The default array value to set
     */
    private function initialize_array_option($option_name, $default_value = []) {
        global $wpdb;

        error_log("Initializing array option: $option_name");

        // First, try using WordPress functions
        $current_value = get_option($option_name);

        // If option doesn't exist or is not an array, set it
        if ($current_value === false || !is_array($current_value)) {
            error_log("Option $option_name is not an array, resetting it");

            // Try WordPress function first
            update_option($option_name, $default_value);

            // Verify it was set correctly
            $saved_value = get_option($option_name);

            // If still not an array, use direct database approach
            if (!is_array($saved_value)) {
                $table_name = $wpdb->prefix . 'options';
                $serialized_value = serialize($default_value);

                // Check if option exists in database
                $option_exists = $wpdb->get_var(
                    $wpdb->prepare(
                        "SELECT COUNT(*) FROM $table_name WHERE option_name = %s",
                        $option_name
                    )
                );

                if ($option_exists) {
                    // Update existing option
                    $wpdb->query(
                        $wpdb->prepare(
                            "UPDATE $table_name SET option_value = %s WHERE option_name = %s",
                            $serialized_value,
                            $option_name
                        )
                    );
                } else {
                    // Insert new option
                    $wpdb->query(
                        $wpdb->prepare(
                            "INSERT INTO $table_name (option_name, option_value, autoload) VALUES (%s, %s, %s)",
                            $option_name,
                            $serialized_value,
                            'yes'
                        )
                    );
                }

                if ($wpdb->last_error) {
                    error_log("Error updating option $option_name: " . $wpdb->last_error);
                } else {
                    error_log("Successfully updated option $option_name in database");

                    // Clear caches to ensure fresh data
                    wp_cache_delete('alloptions', 'options');
                    wp_cache_delete('notoptions', 'options');
                    wp_cache_delete($option_name, 'options');
                }
            } else {
                error_log("Successfully initialized option $option_name as an array");
            }
        } else {
            error_log("Option $option_name is already an array, no action needed");
        }
    }

    /**
     * Fix option formats for any critical options that might be corrupted
     * This is especially important for options that should be arrays but might be stored as strings
     */
    private function fix_option_formats() {
        global $wpdb;

        error_log("Running fix_option_formats to repair any corrupted options");

        // List of critical options that must be arrays
        $array_options = [
            'active_plugins',
            'deactivated_plugins',
            'recently_activated',
            'wp_user_roles',
            'theme_mods_' . get_stylesheet(),
            'widget_pages',
            'widget_calendar',
            'widget_archives',
            'widget_media_audio',
            'widget_media_image',
            'widget_media_gallery',
            'widget_media_video',
            'widget_meta',
            'widget_search',
            'widget_text',
            'widget_categories',
            'widget_recent-posts',
            'widget_recent-comments',
            'widget_rss',
            'widget_nav_menu',
            'widget_custom_html',
            'uninstall_plugins',
            'recovery_keys',
            'recovery_mode_email_last_sent'
        ];

        // Fix each option that should be an array
        foreach ($array_options as $option_name) {
            $value = get_option($option_name);

            // If option exists but is not an array, reset it
            if ($value !== false && !is_array($value)) {
                error_log("Found corrupted option '$option_name' that should be an array but is " . gettype($value));

                // For roles, use our comprehensive initialization
                if ($option_name === 'wp_user_roles') {
                    $this->initialize_wp_roles(get_current_blog_id());
                } else {
                    // For other options, reset to empty array
                    $this->initialize_array_option($option_name, array());
                }
            }
        }

        // Check for transients and site transients that might be malformed
        $table_name = $wpdb->prefix . 'options';
        $problematic_options = $wpdb->get_results(
            "SELECT option_name FROM $table_name 
            WHERE option_name LIKE '%transient%' 
            OR option_name LIKE '%widget%' 
            OR option_name LIKE '%plugin%'"
        );

        if ($problematic_options) {
            foreach ($problematic_options as $option) {
                $option_name = $option->option_name;
                $value = get_option($option_name);

                // If it's a serialized string but corrupted, delete it
                if (is_string($value) && preg_match('/^[aos]:\d+:/', $value) && !@unserialize($value)) {
                    error_log("Deleting corrupted serialized option: $option_name");
                    delete_option($option_name);
                }
            }
        }

        // Also add filters to prevent WordPress from using these potentially corrupted values
        add_filter('option_widget_pages', function($value) {
            return is_array($value) ? $value : array();
        }, 999);

        // Add safety net for theme mods
        add_filter('option_theme_mods_' . get_stylesheet(), function($value) {
            return is_array($value) ? $value : array();
        }, 999);

        // Add a general safety filter for widget options
        add_filter('option_sidebars_widgets', function($value) {
            return is_array($value) ? $value : array('wp_inactive_widgets' => array());
        }, 999);

        // Fix corrupted caches
        wp_cache_flush();

        error_log("Completed fix_option_formats");
    }
}

new Rex_Multisite_Demo();
