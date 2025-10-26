<?php
/**
 * Plugin Name: Rex Multisite Demo
 * Description: Creates per-user demo sites with 1-hour expiry and auto-login.
 * Version: 1.0.3
 * Author: RexTheme
 */

if (!defined('ABSPATH')) exit;

class Rex_Multisite_Demo {

    private $base_sites = [
            'wpvr' => 1,
            'pfm' => 1,
            'cart-lift' => 1,
    ];

    // Define plugin packages for each demo type
    private $plugin_packages = [
            'wpvr' => [
                    'wpvr/wpvr.php',
                    'wpvr-pro/wpvr-pro.php'
            ],
            'pfm' => [
                    'best-woocommerce-feed/best-woocommerce-feeds.php',
                    'best-woocommerce-feed-pro/best-woocommerce-feed-pro.php',
                    'woocommerce/woocommerce.php'
            ],
            'cart-lift' => [
                'cart-lift/cart-lift.php',
                'cart-lift-pro/cart-lift-pro.php',
                'woocommerce/woocommerce.php'
            ],
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

            // Clone only the selected plugin's options
            $this->clone_selected_plugin_options($plugin, $base_id, $blog_id);

            // Copy content from the base site and activate only the selected plugin
            $this->copy_site_content($base_id, $blog_id, $plugin, $user_key, $domain);

            // Create demo user with admin privileges
            $demo_url = $this->create_demo_user($blog_id, $user_key, $domain);

            error_log("Demo site successfully created: $domain (ID: $blog_id)");

            // Return success response
            wp_send_json_success([
                    'url' => $demo_url,
                    'site_id' => $blog_id,
                    'domain' => $domain,
                    'expires' => date('Y-m-d H:i:s', time() + 3600)
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
        update_option('_demo_expiry', time() + 3600); // 1 hour

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

    /** Copy content from template site and activate selected plugins */
    private function copy_site_content($base_id, $new_site_id, $plugin, $user_key, $subdomain) {
        error_log("Setting up demo site for $plugin from template site $base_id");

        // Copy basic template content (clean WordPress install)
        $this->copy_template_content($base_id, $new_site_id);

        // Switch to new site to activate plugins and configure
        switch_to_blog($new_site_id);

        // Activate plugin package for the selected demo
        $this->activate_plugin_package($plugin);


        // Create sample content for the plugin
//        $this->create_plugin_demo_content($plugin);

        restore_current_blog();

        error_log("Demo site setup completed for $plugin");
    }

    /** Copy basic template content (minimal WordPress setup) */
    private function copy_template_content($base_id, $new_site_id) {
        switch_to_blog($base_id);

        // Only copy essential template content
        $essential_options = [
                'template', 'stylesheet',  // Theme
                'blogdescription', 'start_of_week', 'use_balanceTags',
                'use_smilies', 'require_name_email', 'comments_notify',
                'posts_per_rss', 'rss_use_excerpt', 'mailserver_url',
                'mailserver_login', 'mailserver_pass', 'mailserver_port',
                'default_category', 'default_comment_status', 'default_ping_status',
                'default_pingback_flag', 'posts_per_page', 'date_format',
                'time_format', 'links_updated_date_format', 'comment_order',
                'comments_per_page', 'default_comments_page', 'comment_registration',
                'close_comments_for_old_posts', 'close_comments_days_old',
                'thread_comments', 'thread_comments_depth', 'page_comments',
                'comment_moderation', 'moderation_notify', 'permalink_structure',
                'rewrite_rules', 'hack_file', 'upload_url_path', 'thumbnail_size_w',
                'thumbnail_size_h', 'thumbnail_crop', 'medium_size_w', 'medium_size_h',
                'avatar_default', 'avatar_rating', 'uploads_use_yearmonth_folders',
                'embed_autourls', 'embed_size_w', 'embed_size_h',
                'timezone_string', 'show_avatars'
        ];

        $options_to_copy = [];
        foreach ($essential_options as $option_name) {
            $value = get_option($option_name);
            if ($value !== false) {
                $options_to_copy[$option_name] = $value;
            }
        }

        // Copy theme customizations if any
        $theme_mods = get_option('theme_mods_' . get_stylesheet(), []);
        if (!empty($theme_mods)) {
            $options_to_copy['theme_mods_' . get_stylesheet()] = $theme_mods;
        }

        // Get template pages (like Privacy Policy, Sample Page)
        $template_pages = get_posts([
                'post_type' => 'page',
                'post_status' => 'any',
                'numberposts' => -1
        ]);

        restore_current_blog();

        // Apply to new site
        switch_to_blog($new_site_id);

        // Copy essential options
        foreach ($options_to_copy as $option_name => $option_value) {
            update_option($option_name, $option_value);
        }

        // Copy template pages
        foreach ($template_pages as $page) {
            $new_page_data = [
                    'post_title' => $page->post_title,
                    'post_content' => $page->post_content,
                    'post_status' => $page->post_status,
                    'post_type' => 'page',
                    'post_name' => $page->post_name,
                    'menu_order' => $page->menu_order
            ];

            $new_page_id = wp_insert_post($new_page_data);

            // Copy essential page meta
            if ($new_page_id) {
                $meta_to_copy = ['_wp_page_template'];
                foreach ($meta_to_copy as $meta_key) {
                    $meta_value = get_post_meta($page->ID, $meta_key, true);
                    if ($meta_value) {
                        update_post_meta($new_page_id, $meta_key, $meta_value);
                    }
                }
            }
        }

        restore_current_blog();
    }

    /** Activate specific plugin package for the demo */
    private function activate_plugin_package($plugin) {
        if (!isset($this->plugin_packages[$plugin])) {
            error_log("No plugin package defined for: $plugin");
            return;
        }

        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php';

        $plugins_to_activate = $this->plugin_packages[$plugin];
        // Always include rex-plugin-demo-sandbox
        $plugins_to_activate[] = 'rex-plugin-demo-sandbox/rex-plugin-demo-sandbox.php';
        $plugins_to_activate = array_unique($plugins_to_activate);
        $active_plugins = get_option('active_plugins', []);
        error_log('Active plugins before activation: ' . implode(', ', $active_plugins));
        $activation_successful = [];
        $deactivation_successful = [];
        $uninstall_successful = [];
        $uninstall_failed = [];

        // Deactivate and uninstall any plugins not in the list
        foreach ($active_plugins as $plugin_file) {
            if (!in_array($plugin_file, $plugins_to_activate)) {
                deactivate_plugins($plugin_file, true, false);
                $deactivation_successful[] = $plugin_file;
                // Try to uninstall and delete plugin files
                if (is_plugin_active($plugin_file)) {
                    deactivate_plugins($plugin_file, true, false);
                }
                $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($plugin_file);
                if (is_dir($plugin_dir)) {
                    global $wp_filesystem;
                    if (empty($wp_filesystem)) {
                        require_once ABSPATH . '/wp-admin/includes/file.php';
                        WP_Filesystem();
                    }
                    if ($wp_filesystem->delete($plugin_dir, true, 'd')) {
                        $uninstall_successful[] = $plugin_file;
                        error_log("Uninstalled and deleted: $plugin_file");
                    } else {
                        $uninstall_failed[] = $plugin_file;
                        error_log("Failed to delete plugin files: $plugin_file");
                    }
                } else {
                    $uninstall_failed[] = $plugin_file;
                    error_log("Plugin directory not found for uninstall: $plugin_file");
                }
            }
        }
        // Remove deactivated/uninstalled plugins from active_plugins array
        $active_plugins = array_values(array_diff($active_plugins, $deactivation_successful, $uninstall_successful));

        // Activate only the required plugins that exist locally
        foreach ($plugins_to_activate as $plugin_file) {
            $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;
            if (file_exists($plugin_path)) {
                if (!in_array($plugin_file, $active_plugins)) {
                    activate_plugin($plugin_file);
                    $active_plugins[] = $plugin_file;
                    $activation_successful[] = $plugin_file;
                    error_log("Activated: $plugin_file");
                } else {
                    error_log("Already active: $plugin_file");
                }
            } else {
                error_log("Plugin file not found locally: $plugin_file");
            }
        }

        // Update active plugins option
        update_option('active_plugins', array_unique($active_plugins));

        error_log("Activated plugins for $plugin: " . implode(', ', $activation_successful));
        error_log("Uninstalled plugins: " . implode(', ', $uninstall_successful));
        error_log("Failed uninstalls: " . implode(', ', $uninstall_failed));
        error_log("Deactivated plugins: " . implode(', ', $deactivation_successful));
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

    /** Create demo user and return login URL */
    private function create_demo_user($new_site_id, $user_key, $subdomain) {
        switch_to_blog($new_site_id);

        $guest_username = 'demo_admin_' . $user_key;
        $guest_email = $guest_username . '@demo.local';
        $guest_password = wp_generate_password(12, true);
        $expiry = time() + 3600; // 1 hour

        error_log("Creating demo user: $guest_username for site $new_site_id");

        $user_id = wp_create_user($guest_username, $guest_password, $guest_email);

        if (!is_wp_error($user_id)) {
            error_log("Demo user created successfully with ID: $user_id");

            $user = new WP_User($user_id);
            $user->set_role('administrator');
            update_user_meta($user_id, '_demo_expiry', $expiry);

            // Ensure user is added to this site with admin role
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
            $token_key = 'demo_token_' . md5($token);

            // Store token temporarily (full session duration)
            set_transient($token_key, $token_data, 1800);

            error_log("Created token: $token_key");
            error_log("Token expires at: " . date('Y-m-d H:i:s', $token_data['expiry']));

            // Create the demo URL with token
            $demo_url = 'http://' . $subdomain . '/wp-admin/?demo_login=' . urlencode($token);
            error_log("Demo URL created: $demo_url");

        } else {
            error_log('Demo user creation failed: ' . $user_id->get_error_message());
            $demo_url = 'http://' . $subdomain . '/wp-admin/';
        }

        restore_current_blog();
        return $demo_url;
    }

    /** Handle guest token login */
    public function handle_demo_token() {
        if (!isset($_GET['demo_login'])) return;

        $token = sanitize_text_field($_GET['demo_login']);

        try {
            error_log("Processing demo token: " . substr($token, 0, 20) . "...");

            $token_data = json_decode(base64_decode($token), true);

            if (!$token_data || !isset($token_data['user_id']) || !isset($token_data['site_id'])) {
                error_log("Invalid token data structure");
                wp_die('Invalid demo token structure.');
                return;
            }

            error_log("Token data: user_id={$token_data['user_id']}, site_id={$token_data['site_id']}");

            // Check expiry and hash directly if transient is missing
            $stored_data = get_transient('demo_token_' . md5($token));
            $now = time();
            $is_expired = ($token_data['expiry'] < $now);
            $is_hash_valid = (isset($token_data['hash']) && $token_data['hash'] === wp_hash($token_data['user_id'] . $token_data['site_id'] . $token_data['expiry']));

            if (($stored_data && $stored_data['expiry'] < $now) || $is_expired) {
                error_log("Token expired or not found in transients");
                wp_die('Demo session has expired or is invalid.');
                return;
            }
            if (!$is_hash_valid) {
                error_log("Token hash verification failed");
                wp_die('Invalid demo token hash.');
                return;
            }

            $user_id = (int)$token_data['user_id'];
            $site_id = (int)$token_data['site_id'];

            // Switch to correct site if multisite
            if (is_multisite() && get_current_blog_id() !== $site_id) {
                switch_to_blog($site_id);
            }

            // Log in the user
            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id, true);
            do_action('wp_login', get_userdata($user_id)->user_login, get_userdata($user_id));

            // Redirect to dashboard/admin
            $redirect_url = admin_url();
            if (isset($_GET['redirect_to'])) {
                $redirect_url = esc_url_raw($_GET['redirect_to']);
            }
            wp_redirect($redirect_url);
            exit;

        } catch (Exception $e) {
            error_log('Demo token error: ' . $e->getMessage());
            wp_die('Invalid demo token: ' . $e->getMessage());
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
        static $timer_rendered = false;
        if ($timer_rendered) return;
        $timer_rendered = true;
        if (!is_user_logged_in()) return;
        $user_id = get_current_user_id();
        $expiry = get_user_meta($user_id, '_demo_expiry', true);
        if (!$expiry) return;
        $remaining = $expiry - time();
        if ($remaining <= 0) {
            wp_logout();
            wp_redirect(network_home_url());
            exit;
        }
        ?>
        <style>
        #rex-demo-timer {
            position: fixed;
            bottom: 10px;
            right: 10px;
            background: linear-gradient(90deg, #0031ff 0%, #ff5722 100%);
            color: #fff;
            padding: 16px 24px;
            border-radius: 8px;
            z-index: 9999;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 22px;
            font-weight: bold;
            box-shadow: 0 4px 16px rgba(0,0,0,0.25);
            border: 2px solid #fff3e0;
            display: flex;
            align-items: center;
            gap: 10px;
            animation: rex-timer-pop 0.5s;
        }
        #rex-demo-countdown {
            font-size: 28px;
            font-weight: bold;
            color: #fffde7;
            animation: rex-timer-pulse 1s infinite;
            letter-spacing: 2px;
        }
        @keyframes rex-timer-pulse {
            0% { color: #fffde7; text-shadow: 0 0 8px #fffde7; }
            50% { color: #ffe082; text-shadow: 0 0 16px #ff9800; }
            100% { color: #fffde7; text-shadow: 0 0 8px #fffde7; }
        }
        @keyframes rex-timer-pop {
            0% { transform: scale(0.8); }
            100% { transform: scale(1); }
        }
        </style>
        <div id="rex-demo-timer">
            <span style="font-size:30px;">⏰</span>
            Demo Access: <span id="rex-demo-countdown"></span>
        </div>
        <script>
            var remaining = <?php echo intval($remaining); ?>;
            function updateCountdown(){
                var min = Math.floor(remaining / 60);
                var sec = remaining % 60;
                if (sec < 10) sec = '0' + sec;
                document.getElementById('rex-demo-countdown').innerText = min + 'm ' + sec;
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
                set_transient('rex_demo_user_' . $user_id, $expiry, 3600);

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

    /** Generic option cloning for any plugin or option set */
    public function clone_options($option_names, $source_blog_id, $target_blog_id) {
        switch_to_blog($source_blog_id);
        $options = [];
        foreach ($option_names as $name) {
            $options[$name] = get_option($name);
        }
        restore_current_blog();
        switch_to_blog($target_blog_id);
        foreach ($options as $name => $value) {
            update_option($name, $value);
        }
        restore_current_blog();
    }

    /** Clone only the selected plugin's options for the demo site */
    public function clone_selected_plugin_options($plugin, $source_blog_id, $target_blog_id) {
        $plugin_options = [
            'wpvr' => [
                'wpvr_version',
                'wpvr_installed_time',
                'wpvr_edd_license_key',
                'wpvr_edd_license_status',
                'wpvr_edd_license_data',
                'wpvr_is_premium',
            ],
            'pfm' => [
                'wpfm_version',
                'wpfm_installed_time',
                'wpfm_pro_license_key',
                'wpfm_pro_license_status',
                'wpfm_pro_license_data',
                'wpfm_is_premium',
            ],
            'cart-lift' => [
                'rex_cart_lift_version',
                'rex_cart_lift_installed_time',
                'cart_lift_license_status',
                'cart_lift_license_key',
                'cart_lift_is_premium',
            ],
        ];
        if (isset($plugin_options[$plugin])) {
            $this->clone_options($plugin_options[$plugin], $source_blog_id, $target_blog_id);
        }
    }
}

new Rex_Multisite_Demo();

