<?php
/*
Plugin Name: Amereservant PowerPress Auth
Plugin URI: http://amereservant.com
Description: Fixes HTTP Authentication for PHP CGI module and creates a user-token system for authentication of private feeds so feeds validate on iOS devices.  The correct .htaccess rules must also be added for the PHP CGI fix.
Version: 1.1
Author: Amereservant
Author URI: http://amereservant.com/
*/
/**
 * Initialize Hooks
 *
 * Adds the authentication hooks to Blubrry PowerPress plugin so a token can be used.
 *
 * @param   void
 * @return  void
 * @access  private
 * @since   1.0
 */
function _amere_ppaa_init()
{
    add_filter('powerpress_feed_auth', '_amere_ppaa_cgi_fix', 10, 2);
    add_filter('powerpress_feed_auth', '_amere_ppaa_use_alt_auth', 10, 3);
}
add_action('init', '_amere_ppaa_init');

/**
 * Use Alternative Authentication
 *
 * Determines if the HTTP Authentication should be overridden based on whether or not
 * a token has been detected.
 * This is required since iOS podcasts won't validate if presented with HTTP Authentication.
 *
 * The token is validated against a user ID to see if the token is valid or not.
 * This function could be improved by using a token generation/re-generation process
 * for better security reasons.
 *
 * @param   bool    $default    Whether or not to override HTTP Authentication.
 * @param   string  $error      An error message why authentication failed.
 * @return  bool                (bool)TRUE if token passes and HTTP Auth should be skipped,
 *                              (bool)FALSE if token fails.
 * @access  private
 * @since   1.0
 */
function _amere_ppaa_use_alt_auth( $default, $type, $slug )
{
    $token = _amere_ppaa_get_token();
    
    if( $token && strlen($token) > 30 )
    {
        //var_dump($token);
        $user_id = get_option('_ameretoken_'. $token);
        //var_dump($user_id);exit;
        if( $user_id )
            return true;
        
        return false;
    }
    elseif( isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']) )
    {
        $user = wp_authenticate($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);

        if( !is_wp_error($user) )
        {
            $FeedSettings = get_option('powerpress_feed_'.$slug);
            if( $user->has_cap($FeedSettings['premium']) )
                _amere_ppaa_powerpress_feed_auth_success( $user, $slug );
        }
        return false;
    }
    return $default;
}

/**
 * HTTP Auth Success
 *
 * After a user signs in via HTTP Authentication, this function creates a token
 * for the user and redirects them to the new URL that includes the token.
 * This is so a user can login via Safari on an iOS device, then be redirected
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
 * @since   1.0
 */
function _amere_ppaa_powerpress_feed_auth_success( $user, $feed_slug )
{
    // Generate token using MD5 hash from user's username and the current feed slug
    $token = '_ameretoken_'. md5($user->data->user_login . $feed_slug);

    // Store the token as an option with the user ID as the value.
    // This should probably be stored as a single plugin option with tokens as array values
    add_option($token, $user->ID);
    
    global $wp, $wp_rewrite;

    // Create the feed URL with the token added to it
    if( $wp_rewrite->using_permalinks() )
        $url = home_url($wp->request) .'/'. $token .'/';
    else
        $url = add_query_arg('ftoken', $token, home_url($wp->request) .'/');
    //$current_url = add_query_arg( $wp->query_string, '', home_url( $wp->request ) .'/' );

    // Redirect the user to the new URL
    wp_redirect($url, 301);
    exit;
}
add_action('powerpress_feed_auth_success', '_amere_ppaa_powerpress_feed_auth_success', 1, 2);

/**
 * Get Authentication Token
 *
 * Attempts to retrieve the authentication token.
 *
 * @param   void
 * @return  string|bool     The token if successful, (bool)FALSE if not
 * @access  private
 * @since   1.0
 */
function _amere_ppaa_get_token()
{
    global $wp_query, $wp_rewrite;

    if( $wp_rewrite->using_permalinks() )
    {
        $token = $wp_query->query_vars['ftoken'];
    }
    else
    {
        if( isset($_SERVER['REDIRECT_QUERY_STRING']) )
            parse_str($_SERVER['REDIRECT_QUERY_STRING'], $token);
        else
            $token = isset($_GET['ftoken']) ? array('ftoken' => $_GET['ftoken']) : false;
        
        $token = isset($token['ftoken']) ? $token['ftoken']:$token;
    }
    return $token;
}

/**
 * Add Token Rewrite Rules
 *
 * Adds rewrite rules to WordPress to support the authentication token in private
 * feeds.
 *
 * @param   object  $wp_rewrite     The WP_Rewrite object to append the rules to
 * @return  object                  The WP_Rewrite object
 * @access  private
 * @since   1.0
 */
function _amere_ppaa_rewrite_rules( $wp_rewrite )
{
    $rules = array(
        '(feed|rss|rss2|atom)/(.*)/_ameretoken_([0-9a-zA-Z]+)/?$' => 'index.php?'.
        $wp_rewrite->preg_index(1) .'='. $wp_rewrite->preg_index(2) .'&ftoken='.
        $wp_rewrite->preg_index(3)
    );
    $wp_rewrite->rules = $rules + $wp_rewrite->rules;
}
add_action('generate_rewrite_rules', '_amere_ppaa_rewrite_rules');

/**
 * Add Rewrite Query Var
 *
 * Adds the ftoken query variable to WordPress' URL parameters
 *
 * @param   array   $query_vars The existing query vars to append to
 * @return  array               The query vars with the ftoken param appended
 * @access  private
 * @since   1.0
 */
function _amere_ppaa_add_query_vars($query_vars)
{
    $query_vars[] = 'ftoken';
    return $query_vars;
}
add_filter('query_vars', '_amere_ppaa_add_query_vars');

/**
 * HTTP Authentication Fix for CGI
 *
 * Fixes the HTTP Authentication issue for servers running PHP as CGI instead of
 * as an Apache module.
 *
 * The following .htaccess rule must be added to the .htaccess file:
 * <code>
 *  # Fix for AUTH on CGI PHP
 *  RewriteCond %{HTTP:Authorization} !^$
 *  RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
 * </code>
 *
 * @param   void
 * @return  void
 * @access  private
 * @since   1.0
 */
function _amere_ppaa_cgi_fix( $val )
{
    if( isset($_SERVER['HTTP_AUTHORIZATION']) )
        list($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) = explode(':', base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], 6)));
    
    return $val;
}

