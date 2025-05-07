<?php
include "whois.php";

$whois = new Whois();
$domain = '';

class WhoIsInfoAjaxApi {
    function domainSeperator($domain) {
        if (empty($domain)) {
            return "Domain bilgisi bulunamadı.";
        }
        $domain = strip_tags($domain);

        $explodedDomain = explode(".", $domain);
        $explodedCount = count($explodedDomain);
        if(empty($explodedDomain[$explodedCount-2])){
            return "Unvalid Domain Format";
        }
        $domainArr = array_slice($explodedDomain, 1);
        $tld = implode(".", $domainArr);
        return $tld;

    }
    function whoIsServerConn($domain) {
        global $whois; // Access $whois object defined outside the function

        // Check if domain is provided
        if (!empty($domain)) {
            $parsedExt = $this->domainSeperator($domain);
            if (isset($whois->whoisServers[$parsedExt])) {
                $whois_server = $whois->whoisServers[$parsedExt];
                $fp = fsockopen($whois_server, 43);
                if (!$fp) {
                    return json_encode(["error" => "Unable to connect to WHOIS server"]);
                }
                fwrite($fp, $domain . "\r\n");
                $response = '';
                while (!feof($fp)) {
                    $response .= fgets($fp, 128);
                }
                fclose($fp);

                // Return response as JSON
                //return json_encode(["domain" => $domain, "whois" => $response]);
                return $response;
            } else {
                return json_encode(["error" => "WHOIS server not found for the specified extension"]);
            }
        } else {
            return json_encode(["error" => "Domain information is missing"]);
        }
    }
    function parseDomainInfo($response): array
    {
        $domainKeywords = [
            ['Domain Name' => ['Domain Name', 'domain name', 'Domain name', 'Domain', 'DOMAIN NAME', 'domain']],
            ['Domain ID' => ['Domain ID', 'Domain Name ID', 'Registry Domain ID', 'ROID']],
            ['Updated Date' => ['Last updated on', 'last-update', 'Last Update Time', 'Updated Date', 'Domain Last Updated Date', 'last modified', 'Domain record last updated', 'Last updated']],
            ['Created Date' => ['Creation Date', 'Created On', 'Created on..............', 'Registration Time', 'Domain Create Date', 'Domain Registration Date', 'Domain Name Commencement Date', 'created', 'Domain record activated', 'Registered on']],
            ['Expiry Date' => ['Expiry Date', 'Expiration Date', 'Expires on..............', 'Expiration Time', 'Domain Expiration Date', 'Registrar Registration Expiration Date', 'Record expires on', 'Registry Expiry Date', 'renewal date', 'Domain expires', 'paid-till']],
        ];

        $parsedDomain = [];
        $parsedInfoArr = [];
        $replacedResponse = str_replace("*", " ", $response);
        $trimmedResponse = trim($replacedResponse);
        $lines = explode("\n", $trimmedResponse);

        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) == 2) {
                $key = trim($parts[0]);
                $value = trim($parts[1]);
                if ($key !== 'Domain Servers' && $key !== 'Status' && $key !== 'TERMS OF USE' && $key !== 'Terms of Use' && $key !== 'NOTICE' &&
                    $key !== 'For more information on Whois status codes, please visit https' && $key !== 'by the following terms of use' &&
                    $key !== 'to' && $key !== 'Domain Status' && $key !== 'Name Server' && $key !== 'URL of the ICANN Whois Inaccuracy Complaint Form' &&
                    $key !== '>>> Last update of whois database' && $key !== 'Hidden upon user request' && $value != null) {
                    $parsedInfoArr[$key] = $value;
                }
            }
        }

        foreach ($domainKeywords as $domainKeyword) {
            foreach ($domainKeyword as $var => $keywords) {
                $found = false;
                foreach ($keywords as $keyword) {
                    if (isset($parsedInfoArr[$keyword])) {
                        $parsedDomain[$var] = $parsedInfoArr[$keyword];
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $parsedDomain[$var] = "-";
                }
            }
        }

        return $parsedDomain;
    }
    function parseRegistrarInfo($response): array
    {
        $registrarKeywords = [
            ['WHOIS Server' => ['Whois Server', 'WHOIS SERVER', 'Registrar WHOIS Server', 'admin-contact']],
            ['Registrar URL' => ['Registrar URL', 'Registrar URL (registration services)', 'URL']],
            ['Registrar' => ['Registrar', 'registrar', 'Registrant', 'Registrar Name', 'Created by Registrar', 'Organization Name']],
            ['Handle ID' => ['Registrar IANA ID', 'IANA ID', 'NIC Handle']],
            ['Abuse Mail' => ['Registrar Abuse Contact Email']],
            ['Abuse Phone' => ['Registrar Abuse Contact Phone', 'Phone']],
        ];

        $parsedRegistrar = [];
        $parsedInfoArr = [];
        $replacedResponse = str_replace("*", " ", $response);
        $trimmedResponse = trim($replacedResponse);
        $lines = explode("\n", $trimmedResponse);

        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) == 2) {
                $key = trim($parts[0]);
                $value = trim($parts[1]);
                if ($key !== 'Domain Servers' && $key !== 'Status' && $key !== 'TERMS OF USE' && $key !== 'Terms of Use' && $key !== 'NOTICE' &&
                    $key !== 'For more information on Whois status codes, please visit https' && $key !== 'by the following terms of use' &&
                    $key !== 'to' && $key !== 'Domain Status' && $key !== 'Name Server' && $key !== 'URL of the ICANN Whois Inaccuracy Complaint Form' &&
                    $key !== '>>> Last update of whois database' && $key !== 'Hidden upon user request' && $value != null) {
                    $parsedInfoArr[$key] = $value;
                }
            }
        }

        foreach ($registrarKeywords as $registrarKeyword) {
            foreach ($registrarKeyword as $var => $keywords) {
                $found = false;
                foreach ($keywords as $keyword) {
                    if (isset($parsedInfoArr[$keyword])) {
                        $parsedRegistrar[$var] = $parsedInfoArr[$keyword];
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $parsedRegistrar[$var] = "-";
                }
            }
        }

        return $parsedRegistrar;
    }
    function parseOtherInfo($response): array
    {
        $otherKeywords = [
            ['DNS Secure' => ['DNSSEC']],
            ['Registrant' => ['Registrant', 'registrant', 'org']],
            ['Provider' => ['Reseller', 'Registration Service Provider']],
        ];

        $parsedOtherInfo = [];
        $parsedInfoArr = [];
        $replacedResponse = str_replace("*", " ", $response);
        $trimmedResponse = trim($replacedResponse);
        $lines = explode("\n", $trimmedResponse);

        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) == 2) {
                $key = trim($parts[0]);
                $value = trim($parts[1]);
                if ($key !== 'Domain Servers' && $key !== 'Status' && $key !== 'TERMS OF USE' && $key !== 'Terms of Use' && $key !== 'NOTICE' &&
                    $key !== 'For more information on Whois status codes, please visit https' && $key !== 'by the following terms of use' &&
                    $key !== 'to' && $key !== 'Domain Status' && $key !== 'Name Server' && $key !== 'URL of the ICANN Whois Inaccuracy Complaint Form' &&
                    $key !== '>>> Last update of whois database' && $key !== 'Hidden upon user request' && $value != null) {
                    $parsedInfoArr[$key] = $value;
                }
            }
        }

        foreach ($otherKeywords as $otherKeyword) {
            foreach ($otherKeyword as $var => $keywords) {
                $found = false;
                foreach ($keywords as $keyword) {
                    if (isset($parsedInfoArr[$keyword])) {
                        $parsedOtherInfo[$var] = $parsedInfoArr[$keyword];
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $parsedOtherInfo[$var] = "-";
                }
            }
        }

        return $parsedOtherInfo;
    }
    function parseTheNameserver($response, $extension): array
    {
        $replacedResponse = str_replace("*", " ", $response);
        $trimmedResponse = trim($replacedResponse);
        $nameservers = [];

        if (($extension === "gov.tr" ||$extension === "com.tr" || $extension === "nl" || $extension === 'net.tr' ||$extension === 'org.tr')) {
            $pattern = '/(?:Name Servers|Domain Servers|Domain nameservers|Name servers)\s*:(.*?)(?:Creation Date|Domain record activated|Additional Info|\z)/s';
            preg_match($pattern, $trimmedResponse, $matches);

            // Check if matches were found
            if (isset($matches[1])) {
                // Extract the DNS server names from the matched substring
                $serverInfo = trim($matches[1]);

                // Explode the string by space and merge the resulting array into $nameservers
                $nameservers = array_merge($nameservers, preg_split('/\s+/', $serverInfo));
                $nameservers = $this->removeIPNumbers($nameservers);
            }
        } else {
            $lines = explode("\n", $trimmedResponse);

            foreach ($lines as $line) {
                $parts = explode(':', $line, 2);

                if (count($parts) == 2) {
                    $key = trim($parts[0]);
                    $value = trim($parts[1]);

                    // Check for common nameserver key variants
                    if (in_array($key, ['Name Server', 'Domain Servers', 'Domain nameservers', 'nserver'])) {
                        $nameservers[] = $value;
                    }
                }
            }
        }

        return $this->removeIPNumbers($nameservers);
    }
    function removeIPNumbers(array $array): array
    {
        // Regex pattern to match IPv4 and IPv6 addresses
        $pattern = '/\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\b/';

        // Filter the array to remove elements that match the pattern
        return array_filter($array, function($item) use ($pattern) {
            return !preg_match($pattern, $item);
        });
    }
    function parseStatusCodes($response, $extension): array
    {
        $statusCodeKeywords = [
            'Add Period' => ['addPeriod'],
            'Auto Renew Period' => ['autoRenewPeriod'],
            'Inactive' => ['inactive'],
            'Active' => ['ok', 'Active', 'active', ' active '],
            'Pending Create' => ['pendingCreate'],
            'Pending Delete' => ['pendingDelete'],
            'Pending Renew' => ['pendingRenew'],
            'Pending Restore' => ['pendingRestore'],
            'Pending Transfer' => ['pendingTransfer'],
            'Pending Update' => ['pendingUpdate'],
            'Redemption Period' => ['redemptionPeriod'],
            'Renew Period' => ['renewPeriod'],
            'Server Delete Prohibited' => ['serverDeleteProhibited'],
            'Server Hold' => ['serverHold'],
            'Server Renew Prohibited' => ['serverRenewProhibited'],
            'Server Transfer Prohibited' => ['serverTransferProhibited', 'The domain is LOCKED to transfer.'],
            'Server Update Prohibited' => ['serverUpdateProhibited'],
            'Client Delete Prohibited' => ['clientDeleteProhibited'],
            'Client Hold' => ['clientHold'],
            'Client Renew Prohibited' => ['clientRenewProhibited'],
            'Client Transfer Prohibited' => ['clientTransferProhibited', 'The domain is LOCKED to transfer.'],
            'Client Update Prohibited' => ['clientUpdateProhibited']
        ];

        $classifiedStatuses = [];
        $response = str_replace("*", " ", $response);
        $trimmedResponse = trim($response);

        $patterns = [
            'com.tr' => '/Domain Status: (.*?)\s*Frozen Status: (.*?)\s*Transfer Status: (.*?)\s*Registrant:/s',
            'gov.tr' => '/Domain Status: (.*?)\s*Frozen Status: (.*?)\s*Transfer Status: (.*?)\s*Registrant:/s',
            'org.tr' => '/Domain Status: (.*?)\s*Frozen Status: (.*?)\s*Transfer Status: (.*?)\s*Registrant:/s',
            'net.tr' => '/Domain Status: (.*?)\s*Frozen Status: (.*?)\s*Transfer Status: (.*?)\s*Registrant:/s',
            'nl' => '/Status: (.*?)\s*Registrar:/s',
            'default' => '/(?:Domain Status|Frozen Status|Transfer Status|Status|state): (.*?)[\s\n]/'
        ];

        $pattern = $patterns[$extension] ?? $patterns['default'];
        preg_match_all($pattern, $trimmedResponse, $matches);

        $statusCodes = array_filter(array_slice($matches, 1));

        foreach ($statusCodes as $statuses) {
            foreach ($statuses as $statusCode) {
                foreach ($statusCodeKeywords as $category => $codes) {
                    if (in_array($statusCode, $codes)) {
                        $classifiedStatuses[] = ['status' => $statusCode, 'category' => $category];
                        break;
                    }
                }
            }
        }

        return $classifiedStatuses;
    }
    function cleanRawData($response): string {
        $excludeHeaders = [
            'TERMS OF USE', 'Terms of Use', 'NOTICE',
            'For more information on Whois status codes, please visit https',
            'by the following terms of use', 'to',
            'URL of the ICANN Whois Inaccuracy Complaint Form',
            '>>> Last update of whois database', 'Hidden upon user request'
        ];

        $response = str_replace("*", " ", $response);
        $lines = explode("\n", trim($response));

        $cleanLines = array_filter($lines, function($line) use ($excludeHeaders) {
            foreach ($excludeHeaders as $header) {
                if (stripos($line, $header) !== false) {
                    return false;
                }
            }
            return !empty(trim($line));
        });

        return implode("\n", $cleanLines);
    }
    function displayDomainInfo(array $domainArray,array $registrarArray,array $otherArray,array $nameArray,array $statusArray,$rawdata): string
    {
        $result = [];

        if (empty($domainArray)) {
            $result['error'] = "No domain info found.";
        } else {
            $result['Domain Info'] = $domainArray;
        }
        if (empty($registrarArray)) {
            $result['error'] = "No registrar info found.";
        } else {
            $result['Registrar Info'] = $registrarArray;
        }
        if (empty($nameArray)) {
            $result['error'] = "No nameserver found.";
        } else {
            $result['Nameservers'] = $nameArray;
        }
        if (empty($otherArray)) {
            $result['error'] = "No other info found.";
        } else {
            $result['Other Info'] = $otherArray;
        }
        if (empty($statusArray)) {
            $result['error'] = "No status info found.";
        } else {
            $result['Status Info'] = $statusArray;
        }
        $result["Raw data"]=$rawdata;
        return json_encode($result, JSON_PRETTY_PRINT);
    }

    function whoislookup($domain){
        $rawResponse=$this->whoIsServerConn($domain);
        $domainExtention = $this->domainSeperator($domain);
        $domainarr=$this->parseDomainInfo($rawResponse);
        $registrararr=$this->parseRegistrarInfo($rawResponse);
        $othernarr=$this->parseOtherInfo($rawResponse);
        $nameserverarr=$this->parseTheNameserver($rawResponse,$domainExtention);
        $statusarr=$this->parseStatusCodes($rawResponse,$domainExtention);

        $cleanRawResponse = $this->cleanRawData($rawResponse);


        return $this->displayDomainInfo($domainarr,$registrararr,$othernarr,$nameserverarr,$statusarr,$cleanRawResponse);

    }

    function printJsonResponse($domain) {
        header('Content-Type: application/json');
        echo $this->whoislookup($domain);
    }



}


?>