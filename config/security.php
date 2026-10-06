<?php

declare(strict_types=1);

return [
    'csrf' => [
        'session_key' => '_csrf_token',
    ],
    'headers' => [
        'x_content_type_options' => 'nosniff',
        'x_frame_options' => 'SAMEORIGIN',
        // "0" disables the legacy XSS auditor; "1; mode=block" is deprecated
        // and enabled XS-Leak attacks in the browsers that still honoured it.
        'x_xss_protection' => '0',
        // Only sent on HTTPS responses.
        'strict_transport_security' => 'max-age=31536000; includeSubDomains',
        'referrer_policy' => 'strict-origin-when-cross-origin',
        'content_security_policy' => "default-src 'self'",
    ],
];
