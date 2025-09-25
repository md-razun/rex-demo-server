<?php
/**
 * Plugin Name: Rex Multisite Demo
 * Description: Creates per-user demo sites with 30-min expiry and auto-login.
 * Version: 1.0.3
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
            wp_enqueue_script('rex-demo-js', plugin_dir_url(__FILE__) . 'js/demo-script.js', ['jquery'], '1.0.3', true);

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
                throw new Exception("Failed to create required database tables");
            }

            // Initialize the site properly
            $this->initialize_demo_site($blog_id, $plugin, $user_key, $domain);

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
     * Initialize the demo site with proper options
     */
    private function initialize_demo_site($blog_id, $plugin, $user_key, $domain) {
        error_log("Initializing demo site: $blog_id");

        switch_to_blog($blog_id);

        // Set basic site options
        update_option('siteurl', 'http://' . $domain);
        update_option('home', 'http://' . $domain);
        update_option('blogname', ucfirst($plugin) . ' Demo - ' . $user_key);
        update_option('admin_email', 'demo@' . $domain);
        update_option('_demo_expiry', time() + 1800); // 30 minutes

        // Initialize critical array options to prevent errors
        $this->initialize_array_option('active_plugins', []);
        $this->initialize_array_option('deactivated_plugins', []);
        $this->initialize_array_option('recently_activated', []);

        // Initialize WordPress roles properly
        $this->initialize_wp_roles();

        // Initialize widget options as arrays
        $this->initialize_array_option('sidebars_widgets', ['wp_inactive_widgets' => []]);

        restore_current_blog();

        error_log("Demo site initialization completed: $blog_id");
    }

    /** Copy content from base site to new demo site - FIXED VERSION */
    private function copy_site_content($base_id, $new_site_id, $plugin, $user_key, $subdomain) {
        error_log("Copying content from base site $base_id to new site $new_site_id");

        // Copy options from base site
        switch_to_blog($base_id);
        $options = wp_load_alloptions();

        // Filter out options that shouldn't be copied
        $skip_options = [
                'siteurl', 'home', 'blogname', 'admin_email',
                'users_can_register', 'default_role', '_demo_expiry',
                'upload_path', 'upload_url_path',
                'recently_activated', 'active_plugins', 'deactivated_plugins',
                'wp_user_roles', 'sidebars_widgets'
        ];

        foreach ($skip_options as $skip) {
            unset($options[$skip]);
        }
        restore_current_blog();

        // Switch to new site and set options
        switch_to_blog($new_site_id);

        // Copy filtered options with proper handling
        foreach ($options as $option_name => $option_value) {
            if (!in_array($option_name, $skip_options)) {
                // Properly handle serialized data
                if (is_string($option_value) && $this->is_serialized($option_value)) {
                    $unserialized = @unserialize($option_value);
                    if ($unserialized !== false) {
                        update_option($option_name, $unserialized);
                    } else {
                        // Skip corrupted serialized data
                        error_log("Skipping corrupted serialized option: $option_name");
                        continue;
                    }
                } else {
                    update_option($option_name, $option_value);
                }
            }
        }

        // Copy posts and pages from base site
        $this->copy_posts($base_id, $new_site_id);

        restore_current_blog();

        error_log("Content copying completed from $base_id to $new_site_id");
    }

    /**
     * Check if a string is serialized
     */
    private function is_serialized($data) {
        if (!is_string($data)) {
            return false;
        }
        $data = trim($data);
        if (empty($data)) {
            return false;
        }
        if ($data === 'b:0;' || $data === 'b:1;' || $data === 'N;') {
            return true;
        }
        if (!preg_match('/^([adObis]):/', $data, $badions)) {
            return false;
        }
        switch ($badions[1]) {
            case 'a':
            case 'O':
            case 's':
                if (preg_match("/^{$badions[1]}:[0-9]+:.*[;}]\$/s", $data)) {
                    return @unserialize($data) !== false;
                }
                break;
            case 'b':
            case 'i':
            case 'd':
                if (preg_match("/^{$badions[1]}:[0-9.E+-]+;\$/", $data)) {
                    return true;
                }
                break;
        }
        return false;
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

            $demo_url = 'http://' . $subdomain . '/wp-admin/?demo_login=' . urlencode($token);
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
        if (!is_user_logged_in()) return;

        $user_id = get_current_user_id();
        $expiry = get_user_meta($user_id, '_demo_expiry', true);

        if (!$expiry) return;

        $remaining = $expiry - time();
        if ($remaining <= 0) {
            // Log out expired user
            wp_logout();
            wp_redirect(network_home_url());
            exit;
        }
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
     */
    public function check_demo_user() {
        if (is_user_logged_in()) {
            $user_id = get_current_user_id();
            $expiry = get_user_meta($user_id, '_demo_expiry', true);

            if ($expiry) {
                // Store in a transient for quick access
                set_transient('rex_demo_user_' . $user_id, $expiry, 1800);

                // Fix plugin-related options that could cause dashboard errors
                $this->fix_option_formats();

                // Add protection filters
                add_filter('pre_option_recently_activated', function() { return array(); }, 999);
                add_filter('pre_option_deactivated_plugins', function() { return array(); }, 999);
                add_filter('pre_option_active_plugins', function() { return array(); }, 999);

                // If expired, log them out immediately
                if ($expiry < time()) {
                    wp_logout();
                    wp_redirect(network_home_url());
                    exit;
                }

                // Add demo notice
                if (is_admin()) {
                    add_action('admin_notices', function() {
                        $remaining_minutes = ceil((get_user_meta(get_current_user_id(), '_demo_expiry', true) - time()) / 60);
                        echo '<div class="notice notice-info"><p>You are viewing a demo site. This demo will expire in ' .
                                $remaining_minutes . ' minutes.</p></div>';
                    }, 9999);
                }
            }
        }
    }

    /**
     * Properly initialize WordPress roles
     */
    private function initialize_wp_roles() {
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
                'subscriber' => [
                        'name' => 'Subscriber',
                        'capabilities' => [
                                'read' => true,
                                'level_0' => true,
                        ]
                ]
        ];

        update_option('wp_user_roles', $default_roles);

        // Clear caches
        wp_cache_delete('wp_user_roles', 'options');
    }

    /**
     * Initialize array options properly
     */
    private function initialize_array_option($option_name, $default_value = []) {
        $current_value = get_option($option_name, false);

        if ($current_value === false || !is_array($current_value)) {
            update_option($option_name, $default_value);
            wp_cache_delete($option_name, 'options');
        }
    }

    /**
     * Fix option formats for corrupted options
     */
    private function fix_option_formats() {
        // Critical options that must be arrays
        $array_options = [
                'active_plugins' => [],
                'deactivated_plugins' => [],
                'recently_activated' => [],
                'sidebars_widgets' => ['wp_inactive_widgets' => []]
        ];

        foreach ($array_options as $option_name => $default_value) {
            $value = get_option($option_name, false);

            if ($value !== false && !is_array($value)) {
                error_log("Fixing corrupted option: $option_name");
                update_option($option_name, $default_value);
                wp_cache_delete($option_name, 'options');
            }
        }

        // Add safety filters
        add_filter('option_active_plugins', function($value) {
            return is_array($value) ? $value : [];
        }, 999);

        add_filter('option_deactivated_plugins', function($value) {
            return is_array($value) ? $value : [];
        }, 999);

        add_filter('option_recently_activated', function($value) {
            return is_array($value) ? $value : [];
        }, 999);
    }
}

new Rex_Multisite_Demo();