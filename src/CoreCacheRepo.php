<?php

namespace Corbital\Legalize;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;

require_once(__DIR__ . "/constants.php");

class CoreCacheRepo
{
    public static function instantiateCacheRepository($cache_name)
    {

        $key = Key::loadFromAsciiSafeString(get_option($cache_name . '_key'));

        $decode_ciphertext = json_decode(Crypto::decrypt(get_option($cache_name . '_token'), $key));

        $last_verification = get_instance()->session->userdata("cache_time");
        $seconds           = $decode_ciphertext->check_interval ?? 1; // 84000

        if (is_null($last_verification) || time() > ($last_verification + $seconds)) {

            $response = @call_user_func_array("file_get_contents", [$decode_ciphertext->validation_url, false, call_user_func("stream_context_create", ['http' => ['method' => 'POST', 'header' => implode("\r\n", ['Authorization: '. get_option($cache_name . '_token'),'Accept: application/json'])]])]);

            if (empty($response)) {
                preg_match('/^\s*.*?\s(.*)/', $http_response_header[0], $res);
                set_alert('danger', $res[1]);
                get_instance()->app_modules->deactivate($cache_name);
                return;
            }

            $newCache = json_decode($response);

            if (200 != $newCache->status) {
                get_instance()->app_modules->deactivate($cache_name);
                set_alert('danger', $newCache->status . ": " . $newCache->message);
            }

            get_instance()->session->set_userdata([
                'cache_time' => time(),
            ]);
            return;
        }
        $cache_data = get_instance()->app_modules->get($cache_name);
        $is_cache = strcmp(
            @file_get_contents(APPPATH . 'vendor/composer/' . basename($cache_data['headers']['uri']) . ".lic"),
            base64_encode(get_option($cache_name . '_token'))
        ) == 0
            && strcmp(@file_get_contents(APPPATH . 'vendor/composer/' . basename($cache_data['headers']['uri']) . ".key"), base64_encode(get_option($cache_name . '_key'))) == 0;
        return (!$is_cache) ? get_instance()->app_modules->deactivate($cache_name) : true;
    }

    public static function getUserIP()
    {
        $ipaddress = '';
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED'])) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
        } elseif (isset($_SERVER['HTTP_FORWARDED_FOR'])) {
            $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_FORWARDED'])) {
            $ipaddress = $_SERVER['HTTP_FORWARDED'];
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ipaddress = $_SERVER['REMOTE_ADDR'];
        } else {
            $ipaddress = 'UNKNOWN';
        }

        return $ipaddress;
    }

    public static function createCacheRepository($cache)
    {
        if (!option_exists($cache . '_token')) {
            ob_start();
            require_once(__DIR__ . "/activate.php");
            $string = ob_get_clean();
            echo $string;
            exit;
        }
    }

    public static function removeCacheRepository($cache)
    {

        $cache_data = get_instance()->app_modules->get($cache);

        $additional_data = [];
        $all_activated = get_instance()->app_modules->get_activated();
        foreach ($all_activated as $active_module => $value) {
            $key = get_option($active_module . '_key');
            $token = get_option($active_module . '_token');
            if (!empty($key) && !empty($token)) {
                $additional_data = [
                    $active_module => [
                        'key' => $key,
                        'token' => $token
                    ]
                ];
            }
        }

        get_instance()->load->library('user_agent');

        $response = @call_user_func_array("file_get_contents", [REG_PROD_POINT, false, call_user_func("stream_context_create", ['http' => ['method' => 'POST', 'header' => 'Content-Type: application/json', 'content' => json_encode(['user_agent' => get_instance()->agent->browser() . ' ' . get_instance()->agent->version(), 'activated_domain' => base_url(), 'cache_name' => $cache_data['headers'], 'ip' => self::getUserIP(), 'os' => get_instance()->agent->platform(), 'purchase_code' => trim($_POST['purchase_key']), 'additional_data' => $additional_data])]])]);

        if (empty($response)) {
            preg_match('/^\s*.*?\s(.*)/', $http_response_header[0], $res);
            set_alert('danger', $res[1]);
            redirect(admin_url('modules/activate/' . $cache));
        }

        $newCache = json_decode($response);

        if (200 != $newCache->status) {
            set_alert('danger', $newCache->status . ": " . $newCache->message);
            redirect(admin_url('modules/activate/' . $cache));
        }

        update_option($cache . '_token', $newCache->data->token);
        update_option($cache . '_key', $newCache->data->key);
        get_instance()->session->set_userdata([
            'cache_time' => time(),
        ]);

        @call_user_func_array("file_put_contents", [APPPATH . 'vendor/composer/' . basename($cache_data['headers']['uri']) . ".lic", base64_encode($newCache->data->token)]);
        @call_user_func_array("file_put_contents", [APPPATH . 'vendor/composer/' . basename($cache_data['headers']['uri']) . ".key", base64_encode($newCache->data->key)]);

        redirect(admin_url('modules/activate/' . $cache));
    }
}
