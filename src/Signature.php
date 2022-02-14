<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Signature;

use Seffeng\Signature\Exceptions\SignatureException;
use Seffeng\Signature\Helpers\ArrayHelper;
use Seffeng\Signature\Exceptions\SignatureTimeoutException;

class Signature
{
    /**
     *
     * @var boolean
     */
    protected $debug;

    /**
     *
     * @var string
     */
    protected $accessKeyId;

    /**
     *
     * @var string
     */
    protected $accessKeySecret;

    /**
     * 接口版本
     * @var string
     */
    protected $version;

    /**
     *
     * @var string
     */
    protected $timestamp;

    /**
     *
     * @var array
     */
    protected $config;

    /**
     * 服务器时差
     * @var integer
     */
    protected $timeout = 300;

    /**
     * 签名前缀[签名字符串前面拼接的字符]
     * @var string
     */
    protected $prefix = '';

    /**
     * 签名连接符[签名字符串之间拼接的字符]
     * @var string
     */
    protected $connector = '&';

    /**
     * 签名后缀[签名字符串最后拼接的字符]
     * @var string
     */
    protected $suffix = '';

    /**
     * 请求头app id 对应参数名[$header['Access-Key-Id']]
     * @var string
     */
    protected $headerAccessKeyId = 'Access-Key-Id';

    /**
     * 请求头时间戳 对应参数名[$header['Timestamp']]
     * @var string
     */
    protected $headerTimestamp = 'Timestamp';

    /**
     * 请求头Signature对应参数名[$header['Signature']]
     * @var string
     */
    protected $headerSignature = 'Signature';

    /**
     * 请求头Signature对应标签[$header['Signature'] = "Signature $sign"]
     * @var string
     */
    protected $headerSignatureTag = 'Signature';

    /**
     * 请求头Version对应标签[$header['Version']]
     * @var string
     */
    protected $headerVersion = 'Version';

    /**
     * 签名字符串
     * @var string
     */
    protected $signature;

    /**
     *
     * @var string
     */
    protected $algo = 'sha1';

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param array $options
     */
    public function __construct(string $accessKeyId, string $accessKeySecret, array $optoins = [])
    {
        $this->setAccessKeyId($accessKeyId);
        $this->setAccessKeySecret($accessKeySecret);
        $this->debug = ArrayHelper::getValue($optoins, 'debug');
        $this->config = $optoins;
        if ($this->config) {
            $this->loadConfig();
        }
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param string $method
     * @param string $uri
     * @param array $params
     * @return string
     */
    public function sign(string $method, string $uri, array $params = [])
    {
        $this->setSignature($method, $uri, $params);
        return $this->getSignature();
    }

    /**
     * 签名验证
     * @author zxf
     * @date   2020年9月14日
     * @param string $signature
     * @param string $method
     * @param string $uri
     * @param array $params
     * @return boolean
     */
    public function verify(string $signature, string $method, string $uri, array $params = [])
    {
        if ($this->getIsDebug()) {
            return true;
        } else {
            if ($this->verifyTimestamp($this->getTimestamp())) {
                return hash_equals($this->sign($method, $uri, $params), $signature);
            }
            throw new SignatureTimeoutException('Timestamp is expired.');
        }
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param array $headers
     * @return array
     */
    public function getHeaders(array $headers = [])
    {
        return array_merge($headers, [
            $this->getHeaderAccessKeyId() => $this->getAccessKeyId(),
            $this->getHeaderTimestamp() => $this->getTimestamp(),
            $this->getHeaderSignature() => $this->getSignature(),
            $this->getHeaderVersion() => $this->getVersion()
        ]);
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getAccessKeyId()
    {
        return $this->accessKeyId;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param string $accessKeyId
     */
    public function setAccessKeyId(string $accessKeyId)
    {
        $this->accessKeyId = $accessKeyId;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getAccessKeySecret()
    {
        return $this->accessKeySecret;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param string $accessKeySecret
     */
    public function setAccessKeySecret(string $accessKeySecret)
    {
        $this->accessKeySecret = $accessKeySecret;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getHeaderAccessKeyId()
    {
        return $this->headerAccessKeyId;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $headerAccessKeyId
     * @return static
     */
    public function setHeaderAccessKeyId(string $headerAccessKeyId)
    {
        $this->headerAccessKeyId = $headerAccessKeyId;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getHeaderSignature()
    {
        return $this->headerSignature;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $headerSignature
     * @return static
     */
    public function setHeaderSignature(string $headerSignature)
    {
        $this->headerSignature = $headerSignature;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getHeaderTimestamp()
    {
        return $this->headerTimestamp;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $headerTimestamp
     * @return static
     */
    public function setHeaderTimestamp(string $headerTimestamp)
    {
        $this->headerTimestamp = $headerTimestamp;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $headerSignatureTag
     * @return static
     */
    public function setHeaderSignatureTag(string $headerSignatureTag)
    {
        $this->headerSignatureTag = $headerSignatureTag;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月15日
     * @return string
     */
    public function getHeaderVersion()
    {
        return $this->headerVersion;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $headerVersion
     * @return static
     */
    public function setHeaderVersion(string $headerVersion)
    {
        $this->headerVersion = $headerVersion;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return static
     */
    public function setVersion(string $version)
    {
        $this->version = $version;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param string $uri
     * @return string
     */
    public function getUri(string $uri = '')
    {
        return $uri;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     */
    public function setTimestamp(int $time = null)
    {
        $this->timestamp = is_null($time) ? time() : $time;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return string
     */
    public function getTimestamp()
    {
        if (is_null($this->timestamp)) {
            $this->setTimestamp();
        }
        return $this->timestamp;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return number
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param int $timeout
     * @return static
     */
    public function setTimeout(int $timeout)
    {
        $this->timeout = $timeout;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param int $timestamp
     * @return boolean
     */
    public function verifyTimestamp(int $timestamp)
    {
        $time = time();
        if (abs($timestamp - $time) > $this->getTimeout()) {
            return false;
        }
        return true;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param array $params
     * @return string
     */
    protected function signParameters(array $params = [])
    {
        $string = $this->getConnector();
        if ($params) {
            ksort($params);
            foreach ($params as $key => $value) {
                if ((is_string($value) || is_numeric($value)) || is_bool($value)) {
                    $string .= urlencode($key) .'='. (is_bool($value) ? ($value === true ? 'true' : 'false') : urlencode($value)) . $this->getConnector();
                }
            }
            $strlen = strlen($this->getConnector());
            $strlen > 0 && $string = substr($string, 0, - $strlen);
        }
        return $string;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param string $signature
     * @return string
     */
    protected function getSignatureWithTag(string $signature)
    {
        return empty($this->headerSignatureTag) ? $signature : ($this->headerSignatureTag . ' ' . $signature);
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @param string $method
     * @param string $uri
     * @param array $params
     * @return static
     */
    protected function setSignature(string $method, string $uri, array $params = [])
    {
        $paramsSign = $this->signParameters($params);
        $signString = $this->getPrefix() . $method . $this->getConnector() . ($this->getVersion() ? (($this->getHeaderVersion() . '='. $this->getVersion()) . $this->getConnector()) : '') .
                      $this->getUri($uri) . $this->getConnector() . $this->getHeaderAccessKeyId(). '=' . $this->getAccessKeyId() .
                      $this->getConnector() . $this->getHeaderTimestamp() . '='. $this->getTimestamp() . $paramsSign . $this->getSuffix();

        $this->signature = $this->getSignatureWithTag(base64_encode(hash_hmac($this->getAlgo(), $signString , $this->getAccessKeySecret(), true)));
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月15日
     * @return string
     */
    public function getAlgo()
    {
        return $this->algo;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $algo
     * @return static
     */
    public function setAlgo(string $algo)
    {
        if (!in_array($algo, hash_hmac_algos())) {
            throw new SignatureException('Warning: the algo is not support.');
        }
        $this->algo = $algo;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月15日
     * @return string
     */
    public function getPrefix()
    {
        return $this->prefix;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $prefix
     * @return static
     */
    public function setPrefix(string $prefix)
    {
        $this->prefix = $prefix;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月15日
     * @return string
     */
    public function getConnector()
    {
        return $this->connector;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $connector
     * @return static
     */
    public function setConnector(string $connector)
    {
        $this->connector = $connector;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月15日
     * @return string
     */
    public function getSuffix()
    {
        return $this->suffix;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param string $suffix
     * @return static
     */
    public function setSuffix(string $suffix)
    {
        $this->suffix = $suffix;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月21日
     * @param bool $isDebug
     * @return static
     */
    public function setDebug(bool $isDebug)
    {
        $this->debug = $isDebug;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @return boolean
     */
    public function getIsDebug()
    {
        return $this->debug;
    }

    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @throws SignatureException
     */
    protected function loadConfig()
    {
        $timeout = ArrayHelper::getValue($this->config, 'timeout');
        $timeout && $this->setTimeout($timeout);

        $version = ArrayHelper::getValue($this->config, 'version');
        $version && $this->setVersion($version);

        $prefix = ArrayHelper::getValue($this->config, 'prefix');
        $prefix && $this->setPrefix($prefix);

        $connector = ArrayHelper::getValue($this->config, 'connector');
        $connector && $this->setConnector($connector);

        $suffix = ArrayHelper::getValue($this->config, 'suffix');
        $suffix && $this->setSuffix($suffix);

        $headerAccessKeyId = ArrayHelper::getValue($this->config, 'headerAccessKeyId');
        $headerAccessKeyId && $this->setHeaderAccessKeyId($headerAccessKeyId);

        $headerTimestamp = ArrayHelper::getValue($this->config, 'headerTimestamp');
        $headerTimestamp && $this->setHeaderTimestamp($headerTimestamp);

        $headerSignature = ArrayHelper::getValue($this->config, 'headerSignature');
        $headerSignature && $this->setHeaderSignature($headerSignature);

        $headerSignatureTag = ArrayHelper::getValue($this->config, 'headerSignatureTag');
        $headerSignatureTag && $this->setHeaderSignatureTag($headerSignatureTag);

        $headerVersion = ArrayHelper::getValue($this->config, 'headerVersion');
        $headerVersion && $this->setHeaderVersion($headerVersion);

        $algo = ArrayHelper::getValue($this->config, 'algo');
        $algo && $this->setAlgo($algo);

        if (empty($this->getAccessKeyId()) || empty($this->getAccessKeySecret())) {
            throw new SignatureException('Warning: accesskeyid, accesskeysecret cannot be empty.');
        }
        if (empty($this->getHeaderAccessKeyId()) || empty($this->getHeaderTimestamp()) || empty($this->getHeaderSignature())) {
            throw new SignatureException('Warning: headerAccessKeyId, headerTimestamp, headerSignature cannot be empty.');
        }
    }
}
