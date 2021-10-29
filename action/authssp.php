<?php
/**
 * DokuWiki Plugin authssp (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Michael Braun <michael-dev@fami-braun.de>
 */

// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();

if (!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');

require_once DOKU_PLUGIN.'action.php';

class action_plugin_authssp_authssp extends DokuWiki_Action_Plugin {

    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook('TPL_METAHEADER_OUTPUT', 'BEFORE', $this, 'handle_tpl_metaheader_output');
        $controller->register_hook('AJAX_CALL_UNKNOWN', 'BEFORE', $this, 'handle_ajax');
        $controller->register_hook('TPL_CONTENT_DISPLAY', 'BEFORE', $this, 'hint_login_if_denied');
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'drop_login_form');
    }

    public function drop_login_form(Doku_Event $event, $param) {
      $event->data = new Doku_Form([]);
    }

    public function hint_login_if_denied(Doku_Event $event, $param) {
        global $ACT, $INFO, $USERINFO, $lang;

        if ($ACT != "denied")
          return;

        if ($USERINFO !== NULL)
          return;

        $link =  tpl_actionlink("login", '', '', '', true);
        $tpl = p_locale_xhtml("denied");

       $event->data = $tpl.$link;

       return true;

    }

    public function handle_ajax(&$event, $param) {
        $call = $event->data;
        if(method_exists($this, "handle_ajax_$call")) {
           $json = new JSON();

           header('Content-Type: application/json');
           try {
             $ret = $this->{"handle_ajax_$call"}();
           } catch (Exception $e) {
             $ret = Array("file" => __FILE__, "line" => __LINE__, "error" => $e->getMessage(), "trace" => $e->getTraceAsString(), "url" => $this->ep_url);
           }
           print $json->encode($ret);
           $event->preventDefault();
        }
    }

    public function handle_ajax_setpersistentlogin() {
        if(!checkSecurityToken()) {
          return Array("file" => __FILE__, "line" => __LINE__, "error" => $this->getLang("CSRF protection."));
        }

        set_doku_pref('authssp', $_POST["value"]);
    }

    public function handle_tpl_metaheader_output(Doku_Event &$event, $param) {
        $path = 'scripts/authssp.js';
        $config = array();
        if ($_REQUEST["do"] == "login") {
          $config['current'] = get_doku_pref('authssp','ask');
          $config['sectok'] = getSecurityToken();
        }
        $json = new JSON();
        $this->include_script($event, 'var authssp_config = '.$json->encode($config));
        $this->link_script($event, DOKU_BASE.'lib/plugins/authssp/'.$path);
    }

    private function include_script($event, $code) {
        $event->data['script'][] = array(
            'type' => 'text/javascript',
            'charset' => 'utf-8',
            '_data' => $code,
        );
    }

    private function link_script($event, $url) {
        $event->data['script'][] = array(
            'type' => 'text/javascript',
            'charset' => 'utf-8',
            'src' => $url,
            'defer' => true
        );
    }
}

// vim:ts=4:sw=4:et:
