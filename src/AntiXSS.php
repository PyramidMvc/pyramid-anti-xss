<?php
/**
 * App          : Pyramid PHP Fremework
 * Packege Name : AntiXSS
 * Author       : Nihat Doğan
 * Email        : info@pyramid.com
 * Website      : https://www.pyramid.com
 * Created Date : 01/01/2025
 * License GPL
 *
 */
namespace Pyramid;

class AntiXSS
{
    // XSS'yi engellemek için karakter değişim tablosu
    private static $xssCleanPatterns = [
        // Script etiketleri
        '/<script\b[^>]*>(.*?)<\/script>/is' => '',
        '/<script\b[^>]*>(.*?)<\/script\b[^>]*>/is' => '',
        // İframe etiketleri
        '/<iframe\b[^>]*>(.*?)<\/iframe>/is' => '',
        // Style etiketleri
        '/<style\b[^>]*>(.*?)<\/style>/is' => '',
        // HTML yorumları
        '/<![\s\S]*?--[ \t\n\r]*>/is' => '',
        // Inline Event Handlers
        '/on[a-z]+\s*=\s*["\'].*?["\']/is' => '',
        // JavaScript URI
        '/javascript\s*:\s*[^"\']*/is' => '',
        // vbscript URI
        '/vbscript\s*:\s*[^"\']*/is' => '',
        // Data URI
        '/data\s*:\s*[^"\']*/is' => '',
        // Base64 Encoded Script
        '/data\s*:\s*image\/(gif|jpeg|png|jpg|x-icon|bmp|vnd.microsoft.icon)\s*;\s*base64\s*,.*/is' => '',
        // Base tags
        '/<base\b[^>]*>(.*?)<\/base>/is' => '',
    ];

    function xss_clean($data)
    {
        // &entity\n; öğesini düzelt
        $data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
        $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
        $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
        $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

        // "on" veya xmlns ile başlayan tüm öznitelikleri kaldırın
        $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

        // javascript: ve vbscript: protokollerini kaldırın
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

        // Yalnızca IE'de çalışır: <span style="width: expression(alert('Ping!'));"></span>
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

        // Ad alanlı öğeleri kaldırın (onlara ihtiyacımız yok)
        $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

        do
        {
            // Gerçekten istenmeyen etiketleri kaldırın
            $old_data = $data;
            $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
        }
        while ($old_data !== $data);

        // işimiz bitti...
        return $data;
    }

    public static function cleanHtml($data)
    {
        // Tüm HTML etiketlerini temizle
        $data = strip_tags($data);
        // Geriye kalan verileri HTML özel karakterlerine dönüştür
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }

    public static function stripTags($data, $allowedTags = '')
    {
        // İzin verilen etiketler dışındaki tüm HTML etiketlerini temizle
        return strip_tags($data, $allowedTags);
    }
}
?>
