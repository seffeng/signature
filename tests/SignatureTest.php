<?php  declare(strict_types=1);

namespace Seffeng\Signature\Tests;

use PHPUnit\Framework\TestCase;
use Seffeng\Signature\Exceptions\SignatureException;
use Seffeng\Signature\Signature;

class SignatureTest extends TestCase
{
    /**
     *
     * @author zxf
     * @date   2020年9月14日
     * @throws SignatureException
     * @throws \Exception
     */
    public function testSignature()
    {
        try {
            $method = 'GET';
            $uri = '/text';
            $params = ['perPage' => 20];

            $options = [
                /**
                 // 调试模式[false-验证签名，true-不验证签名]
                 'debug'     => false,

                 // 签名使用的哈希算法
                 'algo'      => 'sha1',

                 // 签名验证超时时间
                 'timeout'   => 300,

                 // 接口版本
                 'version'   => '',

                 // 签名前缀[签名字符串前面拼接的字符]
                 'prefix'    => '',

                 // 签名连接符[签名字符串之间拼接的字符]
                 'connector' => '&',

                 // 签名后缀[签名字符串最后拼接的字符]
                 'suffix'    => '',

                 // 请求头app id 对应参数名[$header['Access-Key-Id']]
                 'headerAccessKeyId'     => 'Access-Key-Id',

                 // 请求头时间戳 对应参数名[$header['Timestamp']]
                 'headerTimestamp'       => 'Timestamp',

                 // 请求头Signature对应参数名[$header['Signature']]
                 'headerSignature'       => 'Signature',

                 // 请求头Signature对应标签[$header['Signature'] = "Signature $sign"]
                 'headerSignatureTag'    => 'Signature',

                 // 请求头Signature对应标签[$header['Version'] = 'version']
                 'headerVersion'         => 'Version',
                 */
            ];

            /**
             * 客户端使用签名
             */
            $client = new Signature('access-key-id', 'access-key-secret', $options);
            // $client->setVersion('v1');
            // $client->setAlgo('md5');
            $client->sign($method, $uri, $params);
            $headers = $client->getHeaders();
            print_r($headers);
            // 通过请求传递 $headers，如使用 GuzzleHttp
            // $httpClient = new Client(['base_uri' => Signature::getHost()]);
            // $request = $httpClient->get('/test', ['headers' => $headers, 'query' => $params]);

            /**
             * 服务端验证签名
             */
            $server = new Signature('access-key-id', 'access-key-secret', $options);
            $timestamp = 1600659800;
            $signature = 'Signature TN4kbBUDK7km3B0qjXrHhrtek4Q=';
            // $server->setAlgo('md5');
            // $server->setVersion('v1');
            // $server->setTimeout(60);
            $verify = $server->setTimestamp($timestamp)->verify($signature, $method, $uri, $params);
            var_dump($verify);
            if (!$verify) {
                throw new SignatureException('签名无效！');
            }
        } catch (SignatureException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw $e;
        }
    }
}
