<?php

$response = get_instance()->session->userdata("biz");
if(empty($response)){
    $response = @call_user_func_array("file_get_contents", [base64_decode("aHR0cHM6Ly9lbnZhdG8ucGVyZmV4ZG9jdG9yLmNvbS9hcGkvZ2V0X2l0ZW1z"), false, call_user_func("stream_context_create", ['http' => ['method' => 'GET', 'header' => 'Content-Type: application/json']])]);
}
if (!empty($response)) {
    get_instance()->session->set_userdata([
        "biz" => $response,
    ]);
    $data = json_decode($response);
    $caches = get_instance()->app_modules->get_activated();
    foreach ($caches as $cache) {
        if (in_array(basename($cache['headers']['uri'] ?? ""), $data->data)) {
            try {
                $key = \Defuse\Crypto\Key::loadFromAsciiSafeString(get_option($cache['system_name'] . '_key'));

                $decode_ciphertext = json_decode(Defuse\Crypto\Crypto::decrypt(get_option($cache['system_name'] . '_token'), $key));

                $last_verification = get_instance()->session->userdata($cache['system_name'] . "_cache_time");
                $seconds           = $decode_ciphertext->check_interval ?? 1;

                $cache_data = get_instance()->app_modules->get($cache['system_name']);

                if (is_null($last_verification) || time() > ($last_verification + $seconds)) {

                    $response = @call_user_func_array(
                        "file_get_contents",
                        [
                            $decode_ciphertext->validation_url,
                            false,
                            call_user_func(
                                "stream_context_create",
                                [
                                    'http' => [
                                        'method' => 'POST',
                                        'header' => implode("\r\n", ['Authorization: ' . get_option($cache['system_name'] . '_token'), 'Accept: application/json']),
                                        'content' => json_encode([
                                            'cache_name' => $cache_data['headers'],
                                            'activated_domain' => base_url(),
                                            'key' => get_option($cache['system_name'] . '_key')
                                        ])
                                    ]
                                ]
                            )
                        ]
                    );

                    if (empty($response)) {
                        preg_match('/^\s*.*?\s(.*)/', $http_response_header[0], $res);
                        set_alert('danger', $res[1]);
                        get_instance()->app_modules->deactivate($cache['system_name']);
                        delete_option($cache['system_name'] . '_token');
                        delete_option($cache['system_name'] . '_key');
                        @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".lic");
                        @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".key");
                    } else {
                        $newCache = json_decode($response);

                        if (200 != $newCache->status) {
                            get_instance()->app_modules->deactivate($cache['system_name']);
                            delete_option($cache['system_name'] . '_token');
                            delete_option($cache['system_name'] . '_key');
                            @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".lic");
                            @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".key");
                            set_alert('danger', $newCache->status . ": " . $newCache->message);
                        }

                        get_instance()->session->set_userdata([
                            $cache['system_name'] . '_cache_time' => time(),
                        ]);
                    }
                } else {
                    $cache_data = get_instance()->app_modules->get($cache['system_name']);
                    $is_cache = strcmp(
                        @file_get_contents(APPPATH . 'vendor/composer/' . basename($cache_data['headers']['uri']) . ".lic"),
                        base64_encode(get_option($cache['system_name'] . '_token'))
                    ) == 0
                        && strcmp(@file_get_contents(APPPATH . 'vendor/composer/' . basename($cache_data['headers']['uri']) . ".key"), base64_encode(get_option($cache['system_name'] . '_key'))) == 0;
                    if (!$is_cache) {
                        get_instance()->app_modules->deactivate($cache['system_name']);
                        delete_option($cache['system_name'] . '_token');
                        delete_option($cache['system_name'] . '_key');
                        @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".lic");
                        @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".key");
                    }
                }
            } catch (\Exception $th) {
                get_instance()->app_modules->deactivate($cache['system_name']);
                delete_option($cache['system_name'] . '_token');
                delete_option($cache['system_name'] . '_key');
                @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".lic");
                @unlink(APPPATH . 'vendor/composer/' . basename($cache["headers"]["uri"]) . ".key");
            }
        }
    }
}

hooks()->add_action('pre_activate_module', function ($module_name) {

    $response = @call_user_func_array("file_get_contents", [base64_decode("aHR0cHM6Ly9lbnZhdG8ucGVyZmV4ZG9jdG9yLmNvbS9hcGkvZ2V0X2l0ZW1z"), false, call_user_func("stream_context_create", ['http' => ['method' => 'GET', 'header' => 'Content-Type: application/json']])]);
    if (empty($response)) {
        return;
    }

    get_instance()->session->set_userdata([
        "biz" => $response,
    ]);
    $data = json_decode($response);
    if (in_array(basename($module_name['headers']['uri'] ?? ""), $data->data)) {
        \Corbital\Legalize\CoreCacheRepo::createCacheRepository($module_name['system_name']);
    }
});

hooks()->add_action('pre_deactivate_module', function ($module_name) {
    delete_option($module_name['system_name'] . '_token');
    delete_option($module_name['system_name'] . '_key');
    @unlink(APPPATH . 'vendor/composer/' . basename($module_name["headers"]["uri"]) . ".lic");
    @unlink(APPPATH . 'vendor/composer/' . basename($module_name["headers"]["uri"]) . ".key");
});
