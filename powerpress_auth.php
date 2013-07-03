<?php
/*
Plugin Name: PowerPress Token Auth
Plugin URI: http://amereservant.github.io/powerpress_auth
Description: Creates a user-token system for authentication of private feeds so feeds validate on iOS/similar devices.  This plugin depends on the <a href="http://wordpress.org/plugins/powerpress/" title="Blubrry PowerPress">Blubrry PowerPress</a> plugin.
Version: 1.3
Author: Amereservant
Author URI: http://amereservant.com/
*/

class powerpressAuth
{
   /**
    * Token Prefix
    *
    * @var      string
    * @access   protected
    * @since    1.2
    */
    protected $prefix = '_powerpressAuth_';

   /**
    * Feed Token (without prefix)
    *
    * @var      string
    * @access   private
    * @since    1.3
    */
    private $_token = false;
    
   /**
    * Plugin Options
    *
    * @var      array
    * @access   private
    * @since    1.2
    */
    private $_options;

   /**
    * Plugin Option Name
    *
    * @var      string
    * @access   private
    * @since    1.2
    */
    private $_option_name = '_powerpress_auth_options';
    
   /**
    * Class Constructor
    */
    public function __construct()
    {
        $this->_loadOptions();
        $this->_init();
    }

   /**
    * Initialize Hook
    *
    * Runs any methods needing to be ran at `init` and adds additional hooks.
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.2
    */
    public function _init()
    {
        add_filter('query_vars', array($this, '_addQueryVar'));
        add_filter('rewrite_rules_array', array($this, '_addRewriteRules'));
        add_filter('powerpress_feed_auth', array($this, 'tokenAuth'), 10, 3);
    }

   /**
    * Token Auth
    *
    * Determines of the PowerPress Authentication will be overridden by the provided
    * token or not.  This is primarily to enable private feeds for devices such
    * as the iOS devices, which do not support password-protected podcast feeds.
    *
    * The tokens are unqiue to each registered user.
    *
    * @param    bool    $authenticated  (bool)FALSE that the user isn't authenticated
    * @param    string  $type
    * @param    string  $feed_slug      The slug for the current feed
    * @return   bool                    (bool)TRUE if authentication ok, (bool)FALSE if not
    * @access   public
    * @since    1.2
    */
    public function tokenAuth( $authenticated, $type, $feed_slug )
    {
        $this->_token = get_query_var('token');
        
        // Parse the URL and strip the token if it exists
        $url_parts    = parse_url($_SERVER['REQUEST_URI']);
        $url          = site_url() .'/';

        if( isset($url_parts['query']) )
        {
            parse_str($url_parts['query'], $qp);
            if( $qp )
            {
                unset($qp['token']);
                $qp;
                if(count($qp) > 0)
                    $url .= '?'. build_query($qp);
            }
        }
        elseif( isset($url_parts['path']) )
        {
            // We do two things here ...
            // 1) Strip the token from the URL (if it exists) for the redirect URL
            // 2) Capture the token when the rewrite fails even though the token is present
            $token_pos = strpos($url_parts['path'], 'token');
            if( $token_pos )
            {
                $path       = trim(substr($url_parts['path'], 0, $token_pos), '/');
                $token_prts = explode('/', trim(substr($url_parts['path'], $token_pos), '/'));

                if( isset($token_prts[1]) )
                    $token = trim(str_replace($this->prefix, '', $token_prts[1]));
                else
                    $token = false;

                if( !$this->_token && $token )
                    $this->_token = $token;
                
                if( strlen($path) > 0 )
                    $url .= $path .'/';
            }
        }

        // Try to validate with token
        if( $this->_token && strlen($this->_token) > 30 )
        {
            if( ($user_id = $this->_checkTokenExists()) !== false )
                return true;
            
            // Redirect them back to the login page
            wp_redirect(wp_login_url($url));
        }

        if( is_user_logged_in() )
        {
            $user = wp_get_current_user();
            // Get the PowerPress feed settings for given feed
            $feed_settings = get_option('powerpress_feed_'. $feed_slug);
            
            if( $user->has_cap($feed_settings['premium']) )
                return $this->_authSuccess( $user, $feed_slug );
            else
                die('You do not have permission to access this feed!');
        }

        wp_redirect(wp_login_url($url));
        exit;
        
    }

   /**
     * HTTP Auth Success
     *
     * After a user signs in via HTTP Authentication, this function creates a token
     * for the user (if it doesn't exists already) and redirects them to the new URL 
     * that includes the token.
     *
     * This allows a user to authenticate via Safari on an iOS device, then be redirected
     * to the feed URL that includes the token, which they can then subscribe to via
     * the Podcast app.
     *
     * If the token is present, the function returns void, which allows the user to
     * proceed without further need to authenticate.
     *
     * @param   object  $user       The user object after the user has authenticated via HTTP Auth
     * @param   string  $feed_slug  The slug for the current feed being accessed
     * @return  void
     * @access  private
     * @since   1.2
     */
    function _authSuccess( $user, $feed_slug )
    {
        // Generate token using MD5 hash from user's username and the current feed slug
        $this->_token = wp_hash($user->data->user_login . $feed_slug, 'secure_auth');

        // Store the token if it isn't already stored
        if( !$this->_checkTokenExists() )
        {
            // Store the token as an option with the user ID as the value.
            $this->_options['tokens'][$this->_token] = $user->ID;
            $this->_updateOptions();
        }
        
        global $wp, $wp_rewrite;

        // Create the feed URL with the token added to it
        $url = $this->_generateTokenURL($user, $feed_slug);
        
        // Redirect the user to the new URL
        if( !get_query_var('token') )
        {
            wp_redirect($url, 301);
            exit;
        }
        else
        {
            return true;
        }
    }

   /**
    * Generate Token URL
    *
    * This generates the URL that includes the token.
    *
    * @param    object  $user       WP_User instance for the logged in user
    * @param    string  $feed_slug  The current feed slug the user is being authenticated for
    * @return   string              The URL with the token if successfully validated
    * @access   private
    * @since    1.3
    */
    private function _generateTokenURL( $user, $feed_slug )
    {
        $this->_token = false;
        if( !is_a($user, 'WP_User') )
        {
            trigger_error('Invalid WP_User object!');
            return false;
        }
        if( strlen($feed_slug) < 1 )
        {
            trigger_error('Invalid feed slug given.');
            return false;
        }
        $this->_token = wp_hash($user->data->user_login . $feed_slug, 'secure_auth');

    
        $url = site_url() .'/';
        if( get_option('permalink_structure') )
            $url .= 'feed/'. $feed_slug .'/token/'. $this->prefix . $this->_token .'/';
        else
            $url .= '?'. build_query(array('feed' => $feed_slug, 'token' => $this->prefix . $this->_token));

        return $url;
    }

   /**
    * Load Plugin Options
    *
    * This loads the plugin's options from a single WordPress option value and sets
    * the {@link $_options} property.
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.2
    */
    private function _loadOptions()
    {
        if( ($options = get_option($this->_option_name)) === false )
        {
            $options = array('tokens' => array(), 'user_salts' => array());
            add_option($this->_option_name, $options);
        }

        $this->_options = $options;
    }

   /**
    * Check Token
    *
    * Checks given token to see if it is set and if so, it returns the associated
    * user ID.
    *
    * @uses     $_token         Checks the current token to see if it's valid or not
    *
    * @param    void
    * @return   integer         User ID if token exists, (bool)FALSE if not
    * @access   private
    * @since    1.2
    */
    private function _checkTokenExists()
    {
        // The prefix shouldn't be on there, but we'll just make sure
        $token = str_replace($this->prefix, '', $this->_token);

        if( !isset($this->_options['tokens'][$token]) )
            return false;

        return $this->_options['tokens'][$token];
    }

   /**
    * Update Plugin Options
    *
    * Updates the plugin's options.  If a token is added/removed/modified, this
    * method can be called to store the new values in the database.
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.2
    */
    private function _updateOptions()
    {
        update_option($this->_option_name, $this->_options);
    }

   /**
    * Add Token Query Var
    *
    * Adds the token variable to the URL so WordPress recognizes it.
    *
    * @param    array   $qvars  The existing query vars to add our query var to
    * @return   array           The array of query vars with the appended var
    * @access   private
    * @since    1.2
    */
    public function _addQueryVar( $qvars )
    {
        $qvars[] = 'token';
        return $qvars;
    }

   /**
    * Add Rewrite Rules
    *
    * Adds the token rewrite rules to the feeds.  This method largely consists
    * of code from the Blubrry PowerPress plugin's powerpress.php - powerpress_rewrite_rules_array()
    * function.
    * The rules were modified to support the token system and not interrupt the
    * plugin's handling of the feed.
    *
    * @param    array   $rules  Array of existing rewrite rules to append to.
    * @return   array           Array of rewrite rules with our rules appended.
    * @access   private
    * @since    1.2
    */
    public function _addRewriteRules( $rules )
    {
        global $wp_rewrite,$wpdb;
        $powerpress_settings = get_option('powerpress_general');
        $podcast_feeds       = array('podcast' => true);

        if( isset($powerpress_settings['custom_feeds']) && is_array($powerpress_settings['custom_feeds']) )
            $feeds = array_merge($powerpress_settings['custom_feeds'], $podcast_feeds);

        $merged_slugs = '';
        while( list($feed_slug, $feed_title) = each($feeds) )
        {
            if( strlen($merged_slugs) > 0 )
                $merged_slugs .= '|';

            $merged_slugs .= $feed_slug;
        }

        $rules['feed/('. $merged_slugs .')/token/'. $this->prefix .'(.*)/?$'] = $wp_rewrite->index .'?feed='.
            $wp_rewrite->preg_index(1) .'&amp;token='. $wp_rewrite->preg_index(2);

        reset($feeds);
        while( list($feed_slug, $feed_title) = each($feeds) )
        {
            $page_name_id = $wpdb->get_var(
                $wpdb->prepare("SELECT ID FROM {$wpdb->posts} WHERE post_name=%s", $feed_slug)
            );

            if( $page_name_id )
            {
                $rules[$feed_slug .'/token/'. $this->prefix .'(.*)/?$'] = $wp_rewrite->index .'?'. 
                    build_query(array('pagename' => $feed_slug, 'page_id' => $page_name_id,
                        'token' => $wp_rewrite->preg_index(1)));

                unset($feeds[$feed_slug]);
                continue;
            }

            $category = get_category_by_slug($feed_slug);
            if( $category )
            {
                $slug[$feed_slug .'/token/'. $this->prefix .'(.*)/?$'] = $wp_rewrite->index .'?'. 
                    build_query(array('cat' => $category->term_id, 'token' => $wp_rewrite->preg_index(1)));

                unset($feeds[$feed_slug]);
            }
        }

        if( count($feeds) > 0 )
        {
            reset($feeds);
            $remaining_slugs = '';

            while( list($feed_slug, $feed_title) = each($feeds) )
            {
                if( strlen($remaining_slugs) > 0 )
                    $remaining_slugs .= '|';

                $remaining_slugs .= $feed_slug;
            }

            $rules['feed/('. $remaining_slugs .')/token/'. $this->prefix .'(.*)/?$'] = $wp_rewrite->index .'?'.
                build_query(array('feed' => $wp_rewrite->preg_index(1),
                    'token' => $wp_rewrite->preg_index(2)));
        }
        
        return $rules;
    }

   /**
    * Flush Feed Cache
    *
    * Used to flush the RSS feed cache data.
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.3
    */
    private function _flushCache()
    {
        global $wpdb;
        $wpdb->query("DELETE FROM `{$wpdb->options}` WHERE `option_name` LIKE ('_transient%_feed_%')");
    }
}

add_action('plugins_loaded', create_function('',' new powerpressAuth;'));
