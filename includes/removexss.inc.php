<?php
// RemoveXSS function - strips dangerous XSS content from input

function RemoveXSS($val)
{
    // Stage 1: Strip null bytes and control characters used to obfuscate payloads
    $val = preg_replace('/([\x00-\x08][\x0b-\x0c][\x0e-\x20])/', '', $val);

    // Stage 2: Decode HTML entity obfuscation (hex &#x41; and decimal &#65; forms)
    // Attackers encode payloads to bypass filters - decode them first so Stage 3 can catch them
    $search = 'abcdefghijklmnopqrstuvwxyz';
    $search .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $search .= '1234567890!@#$%^&*()';
    $search .= '~`";:?+/={}[]-_|\'\\';

    for ($i = 0; $i < strlen($search); $i++)
    {
        $val = preg_replace('/(&#[x|X]0{0,8}'.dechex(ord($search[$i])).';?)/i', $search[$i], $val);
        $val = preg_replace('/(&#0{0,8}'.ord($search[$i]).';?)/', $search[$i], $val);
    }

    // Stage 3: Recursively strip dangerous HTML tags and JavaScript event handlers
    // Loop until no more dangerous patterns are found (handles nested obfuscation like <scr<script>ipt>)
    $dangerousTags = array(
        'script', 'iframe', 'embed', 'object', 'base', 'applet',
        'meta', 'link', 'style', 'form', 'input', 'body', 'head',
        'html', 'plaintext', 'xss'
    );

    $dangerousEvents = array(
        'onabort', 'onblur', 'onchange', 'onclick', 'ondblclick',
        'onerror', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup',
        'onload', 'onmousedown', 'onmousemove', 'onmouseout',
        'onmouseover', 'onmouseup', 'onreset', 'onresize', 'onselect',
        'onsubmit', 'onunload', 'onafterprint', 'onbeforeprint',
        'onbeforeunload', 'ondrag', 'ondragend', 'ondragenter',
        'ondragleave', 'ondragover', 'ondragstart', 'ondrop',
        'onfocusin', 'onfocusout', 'oninput', 'oninvalid',
        'onpageshow', 'onpagehide', 'onpointerdown', 'onpointerup',
        'onscroll', 'ontouchstart', 'ontouchend', 'ontouchmove'
    );

    $previous = '';
    while ($previous !== $val) {
        $previous = $val;

        // Strip dangerous tags (opening and closing)
        foreach ($dangerousTags as $tag) {
            $val = preg_replace('/<\/?'.$tag.'[^>]*>/i', '', $val);
        }

        // Strip event handlers (e.g. onmouseover=..., onclick="...")
        foreach ($dangerousEvents as $event) {
            $val = preg_replace('/'.$event.'\s*=\s*["\']?[^"\'>\s]*/i', '', $val);
        }

        // Strip javascript: protocol in attributes
        $val = preg_replace('/javascript\s*:/i', '', $val);

        // Strip vbscript: protocol in attributes
        $val = preg_replace('/vbscript\s*:/i', '', $val);

        // Strip expression() CSS injection
        $val = preg_replace('/expression\s*\(/i', '', $val);
    }

    return $val;
}
