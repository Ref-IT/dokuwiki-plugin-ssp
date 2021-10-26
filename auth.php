<?php

/**
 * SSP. SimpleSAMLphp authentication backend

 * Configuration
 * $this->getConf('authtype') = 'authssp'
 * $this->getConf('plugin')['authssp']['ssp_path'] = # : base for simplesaml installation
 * $this->getConf('plugin')['authssp']['ssp_auth_source'] = # : simplesaml auth source id
 * $this->getConf('plugin')['authssp']['ssp_usersfile'] = # : user details cache file
 * $this->getConf('plugin')['authssp']['ssp_attr_name'] = # : attribute for name
 * $this->getConf('plugin')['authssp']['ssp_attr_mail'] = # : attribute for mail
 * $this->getConf('plugin')['authssp']['ssp_attr_grps'] = # : attribute for groups
 * $this->getConf('plugin')['authssp']['ssp_attr_user'] = # : attribute for userid
 *
 * @author  Jorge Hervás <jordihv@gmail.com>, Lukas Slansky <lukas.slansky@upce.cz>
 * @author  Modification for Weatherwax by Michael Braun <michael-dev@fami-braun.de> (C) 2013-03-08 
 * @license GPL2 http://www.gnu.org/licenses/gpl.html
 * @version 0.3
 * @date    March 2013
 */
 

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_authssp extends DokuWiki_Auth_Plugin {
  protected $users = null;
  // declaration of the auth_simple object 
  protected $as;

  public function __construct() {
    parent::__construct();
    $this->cando['external'] = true;
    $this->cando['logout']   = true;
    $this->success = true;
  }

  /**
   * Return user info (copy from plain.class.php)
   *
   * Returns info about the given user needs to contain
   * at least these fields:
   *
   * name string  full name of the user
   * mail string  email addres of the user
   * grps array   list of groups the user is in
   *
   * @author  Lukas Slansky <lukas.slansky@upce.cz>
   */
  public function getUserData($user, $requireGroups = true){

    if($this->users === null) $this->_loadUserData();
    return isset($this->users[$user]) ? $this->users[$user] : false;
  }

  /**
   * Load all user data (modified copy from plain.class.php)
   *
   * loads the user file into a datastructure
   *
   * @author  Lukas Slansky <lukas.slansky@upce.cz>
   */
  protected function _loadUserData(){

    $this->users = array();

    if(!@file_exists($this->getConf('ssp_usersfile'))) return;

    $lines = file($this->getConf('ssp_usersfile'));
    foreach($lines as $line){
      $line = preg_replace('/#.*$/','',$line); //ignore comments
      $line = trim($line);
      if(empty($line)) continue;

      $row    = explode(":",$line,5);
      $groups = array_values(array_filter(explode(",",$row[3])));

      $this->users[$row[0]]['name'] = urldecode($row[1]);
      $this->users[$row[0]]['mail'] = $row[2];
      $this->users[$row[0]]['grps'] = $groups;
    }
  }
  
  /**
   * Save user data
   *
   * saves the user file into a datastructure
   *
   * @author  Lukas Slansky <lukas.slansky@upce.cz>
   */
  protected function _saveUserData($username, $userinfo) {

    if ($this->users === null) $this->_loadUserData();
    $pattern = '/^' . $username . ':/';
    
    // Delete old line from users file
    if (!io_deleteFromFile($this->getConf('ssp_usersfile'), $pattern, true)) {
      msg('Error saving user data (1)', -1);
      return false;
    }
    $groups = join(',',$userinfo['grps']);
    $userline = join(':',array($username, $userinfo['name'], $userinfo['mail'], $groups))."\n";
    // Save new line into users file
    if (!io_saveFile($this->getConf('ssp_usersfile'), $userline, true)) {
      msg('Error saving user data (2)', -1);
      return false;
    }
    $this->users[$username] = $userinfo;
    return true;
  }

  /**
   * Do external authentication (SSO)
   * Params are not used
   */
  public function trustExternal($user,$pass,$sticky=false){
    global $USERINFO;
 
    $sticky ? $sticky = true : $sticky = false; //sanity check

    // loading of simplesamlphp library
    require_once($this->getConf('ssp_path') . '/lib/_autoload.php');
 
    // create auth object and use api to require authentication and get attributes
    $this->as = new SimpleSAML_Auth_Simple($this->getConf('ssp_auth_source'));

    if (!empty($_SESSION[DOKU_COOKIE]['auth']['info'])) {
      $USERINFO['name'] = $_SESSION[DOKU_COOKIE]['auth']['info']['name'];
      $USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];
      $USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['auth']['info']['grps'];
      $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['auth']['user'];
      return true;
    }
 
    // switch to simplesaml login if action=login or this browser was logged in recently.
    if ($_REQUEST["do"] == "login" || ( get_doku_pref('authssp', '') == 'persistentlogin' )) {
	    set_doku_pref('authssp_orig', 'persistentlogin');
	    set_doku_pref('authssp', 'ask');
	    $this->as->requireAuth();
    }

    if ($this->as->isAuthenticated()) {
	    set_doku_pref('authssp', get_doku_pref('authssp_orig', 'ask'));
	    $attrs = $this->as->getAttributes();
	 
	    // check for valid attributes (not empty) and update USERINFO var from dokuwiki
	    if (!isset($attrs[$this->getConf('ssp_attr_name')][0])) {
	      $this->exitMissingAttribute('Name');
	    }
	    $USERINFO['name'] = $attrs[$this->getConf('ssp_attr_name')][0];
	 
	    if (!isset($attrs[$this->getConf('ssp_attr_mail')][0])) {
	      $this->exitMissingAttribute('Mail');
	    }
	    $USERINFO['mail'] = $attrs[$this->getConf('ssp_attr_mail')][0];
	 
	    // groups may be empty (by default any user belongs to the user group) don't perform empty check
	    $USERINFO['grps'] = array_map('strtolower', $attrs[$this->getConf('ssp_attr_grps')]);
	 
	    if (!isset($attrs[$this->getConf('ssp_attr_user')][0])) {
	      $this->exitMissingAttribute('User');
	    }
	 
	    // save user info
	    if (!$this->_saveUserData($attrs[$this->getConf('ssp_attr_user')][0], $USERINFO)) {
	      return false;
	    }
	 
	    // assign user id to the user global information
	    $_SERVER['REMOTE_USER'] = $attrs[$this->getConf('ssp_attr_user')][0];
	 
	    // assign user id and the data from USERINFO to the DokuWiki session cookie
	    $_SESSION[DOKU_COOKIE]['auth']['user'] = $attrs[$this->getConf('ssp_attr_user')][0];
	    $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;

	    return true;

    } // end if_isAuthenticated()

    auth_logoff();

    return false;
  }
 
  /**
   * exit printing info and logout link
   *
   */
  protected function exitMissingAttribute( $attribute ){
    // get logout link
    $url = $this->as->getLogoutURL();
    $logoutlink = '<a href="' . htmlspecialchars($url) . '">logout</a>';
    die( $attribute . ' attribute missing from IdP. Please ' . $logoutlink . ' to return to login form');
  }
 
  /**
   * Log off the current user from DokuWiki and IdP
   *
   */
  public function logOff(){
    // use the simpleSAMLphp authentication object created in trustExternal to logout
    set_doku_pref('authssp', 'ask');
    if ($this->as->isAuthenticated())
      $this->as->logout('/');
  }
 
}
 
//Setup VIM: ex: et ts=2 enc=utf-8 :
