#!/bin/sh
set -e

SUBSCRIBE_DIR=/etc/nginx/subscribe

# 确保目录存在且 admin 可写
mkdir -p "$SUBSCRIBE_DIR"
chmod 777 "$SUBSCRIBE_DIR"

# 确保所有可写文件存在
[ -f "$SUBSCRIBE_DIR/blacklist.json" ]    || echo "[]" > "$SUBSCRIBE_DIR/blacklist.json"
[ -f "$SUBSCRIBE_DIR/blacklist.conf" ]    || echo "# blacklist" > "$SUBSCRIBE_DIR/blacklist.conf"
[ -f "$SUBSCRIBE_DIR/ua_blacklist.json" ] || echo "[]" > "$SUBSCRIBE_DIR/ua_blacklist.json"
[ -f "$SUBSCRIBE_DIR/ua_custom.conf" ]    || printf 'map $http_user_agent $is_custom_bad_ua {\n    default 0;\n}\n' > "$SUBSCRIBE_DIR/ua_custom.conf"
[ -f "$SUBSCRIBE_DIR/token_blacklist.json" ] || echo "[]" > "$SUBSCRIBE_DIR/token_blacklist.json"
[ -f "$SUBSCRIBE_DIR/token_blacklist_auto.json" ] || echo "[]" > "$SUBSCRIBE_DIR/token_blacklist_auto.json"
[ -f "$SUBSCRIBE_DIR/token_blacklist_map.conf" ] || printf '# Token blacklist map - generated automatically\nmap $arg_token $is_token_blacklisted_arg {\n    default 0;\n}\n\nmap $uri $is_token_blacklisted_path {\n    default 0;\n}\n\nmap $args $is_token_blacklisted_l {\n    default 0;\n}\n\nmap "$is_token_blacklisted_arg$is_token_blacklisted_path$is_token_blacklisted_l" $is_token_blacklisted {\n    default 0;\n    ~1 1;\n}\n' > "$SUBSCRIBE_DIR/token_blacklist_map.conf"
[ -f "$SUBSCRIBE_DIR/whitelist_ips.txt" ] || touch "$SUBSCRIBE_DIR/whitelist_ips.txt"
[ -f "$SUBSCRIBE_DIR/admin_settings.json" ] || echo "{}" > "$SUBSCRIBE_DIR/admin_settings.json"

chmod 666 \
    "$SUBSCRIBE_DIR/blacklist.json" \
    "$SUBSCRIBE_DIR/blacklist.conf" \
    "$SUBSCRIBE_DIR/ua_blacklist.json" \
    "$SUBSCRIBE_DIR/ua_custom.conf" \
    "$SUBSCRIBE_DIR/token_blacklist.json" \
    "$SUBSCRIBE_DIR/token_blacklist_auto.json" \
    "$SUBSCRIBE_DIR/token_blacklist_map.conf" \
    "$SUBSCRIBE_DIR/whitelist_ips.txt" \
    "$SUBSCRIBE_DIR/admin_settings.json"

# 确保日志卷目录和日志文件对 PHP-FPM(www-data) 可写
mkdir -p /var/log/subscribe
chmod 777 /var/log/subscribe
touch /var/log/subscribe/access.log
touch /var/log/subscribe/token_ua_guard.log
chmod 666 /var/log/subscribe/access.log
chmod 666 /var/log/subscribe/token_ua_guard.log

# 后台常驻扫描：同一Token在最近24小时内出现超过5个不同UA时，自动封禁24小时
(
    INTERVAL="${TOKEN_UA_GUARD_SCAN_INTERVAL:-300}"
    while true; do
        php /var/www/html/bin/token_ua_guard.php >/dev/null 2>&1 || true
        sleep "$INTERVAL"
    done
) &

php-fpm -D
exec nginx -g 'daemon off;'
