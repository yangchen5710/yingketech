<?php

namespace Ycstar\Yingketech;

use GuzzleHttp\Client;
use Ycstar\Yingketech\Exceptions\InvalidResponseException;
use Ycstar\Yingketech\Exceptions\InvalidArgumentException;

class Yingke
{
    protected $host;

    protected $appId;

    protected $privateKey;

    protected $publicKey;

    protected $insaicPublicKey;

    protected $decryptKey;

    protected $client;

    public function __construct(array $config)
    {
        if (!isset($config['host'])) {
            throw new InvalidArgumentException("Missing Config -- [host]");
        }

        if (!isset($config['app_id'])) {
            throw new InvalidArgumentException("Missing Config -- [app_id]");
        }

        if (!isset($config['private_key'])) {
            throw new InvalidArgumentException("Missing Config -- [private_key]");
        }

        if (!isset($config['public_key'])) {
            throw new InvalidArgumentException("Missing Config -- [public_key]");
        }

        if (!isset($config['insaic_public_key'])) {
            throw new InvalidArgumentException("Missing Config -- [insaic_public_key]");
        }

        if (!isset($config['decrypt_key'])) {
            throw new InvalidArgumentException("Missing Config -- [decrypt_key]");
        }

        $this->host = $config['host'];
        $this->appId = $config['app_id'];
        $this->privateKey = $config['private_key'];
        $this->publicKey = $config['public_key'];
        $this->insaicPublicKey = $config['insaic_public_key'];
        $this->decryptKey = $config['decrypt_key'];
    }

    /**
     * 查询司机轨迹接口
     * 合作方通过本接口查询服务订单的司机轨迹信息
     * @param array $params
     * @return mixed
     * @throws InvalidResponseException
     */
    public function queryDriverLocus(array $params)
    {
        $result = $this->doRequest('post', '/vsv/third/public/queryDriverLocus', $params);
        return $result;
    }

    /**
     * 查询订单状态接口
     * 合作方通过本接口查询指定订单的状态信息
     * @param array $params
     * @return mixed
     * @throws InvalidResponseException
     */
    public function queryStatus(array $params)
    {
        $result = $this->doRequest('post', '/vsv/third/public/queryStatus', $params);
        return $result;
    }

    /**
     * 取消订单接口
     * 合作方通过本接口取消指定的服务订单
     * @param array $params
     * @return mixed
     * @throws InvalidResponseException
     */
    public function cancelOrder(array $params)
    {
        $result = $this->doRequest('post', '/vsv/third/public/cancelOrder', $params);
        return $result;
    }

    /**
     * 预估里程
     * 合作方通过本接口获取驾驶预估里程
     * @param array $params
     * @return mixed
     * @throws InvalidResponseException
     */
    public function estimateMileage(array $params)
    {
        $result = $this->doRequest('post', '/vsv/third/public/estimateMileage', $params);
        return $result;
    }

    /**
     * 查询影像信息
     * 合作方通过本接口获取验车照片等影像信息
     * @param array $params
     * @return mixed
     * @throws InvalidResponseException
     */
    public function queryImages(array $params)
    {
        $result = $this->doRequest('post', '/vsv/third/public/queryImages', $params);
        return $result;
    }

    /**
     * 下单接口
     * 合作方通过本接口对代驾服务下单
     * @param array $params
     * @return mixed
     * @throws InvalidResponseException
     */
    public function createOrder(array $params)
    {
        $params['orderType'] = "DESIGNATED_DRIVER";
        $result = $this->doRequest('post', '/vsv/third/designatedDriver/createOrder', $params);
        return $result;
    }

    /**
     * 查询订单详情接口
     * 合作方通过本接口查询指定订单的详细信息
     * @param array $params
     * @return mixed
     * @throws InvalidResponseException
     */
    public function queryDetail(array $params)
    {
        $result = $this->doRequest('post', '/vsv/third/designatedDriver/queryDetail', $params);
        return $result;
    }

    private function doRequest(string $method, $uri = '', array $options = [])
    {
        try {
            $milliseconds = $this->getMillisecond();
            $requestId = $milliseconds . rand(1000, 9999);

            $json = json_encode($options, JSON_UNESCAPED_UNICODE);
            $preSign = $json . $milliseconds;
            $signature = $this->sign($preSign);
            if(!$this->verify($preSign,$signature, $this->publicKey)){
                throw new InvalidResponseException('verify failed');
            }

            $uri .= "?appId={$this->appId}&requestId={$requestId}&timeSpan={$milliseconds}&sign={$this->encodeUrlSafeBase64($signature)}";

            $postData = ['data' => $this->aesEncrypt($json)];

            $response = $this->getHttpClient()->request($method, $uri, ['json' => $postData])->getBody()->getContents();

            $result = json_decode($response, true);

            if (!$result) {
                throw new InvalidResponseException('invalid response');
            }
            $resultCode = $result['resultCode'] ?? '0';
            if ($resultCode != "200") {
                $resultMessage = $result['resultMessage'] ?? 'unknown error';
                throw new InvalidResponseException($resultMessage, $resultCode);
            }
            $data = $result['data'] ?? '';
            $decryptData = null;
            try {
                $decryptData = $this->aesDecrypt($data);
            } catch (\Exception $e) {
                throw new InvalidResponseException('response data decrypt fail message: ' . $e->getMessage());
            }
            $timeSpan = $result['timeSpan'] ?? '';
            $sign = $result['sign'] ?? '';
            $decryptData = $decryptData == null ? '' : $decryptData;
            if(!$this->verify($decryptData . $timeSpan,$this->base64UrlDecode($sign), $this->insaicPublicKey)){
                throw new InvalidResponseException('response verify fail');
            }
            return json_decode($decryptData, true);
        } catch (InvalidResponseException $e) {
            throw new InvalidResponseException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * 验签
     * @param $preSign
     * @param $signature
     * @param $publicKey
     * @return bool
     */
    public function verify($preSign, $signature, $publicKey)
    {
        // 将私钥转换为PEM格式
        $publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n";
        $publicKeyPEM .= chunk_split($publicKey, 64, "\n");
        $publicKeyPEM .= "-----END PUBLIC KEY-----\n";
        $pubRes = openssl_get_publickey($publicKeyPEM);

        $bool = openssl_verify($preSign, $signature, $pubRes, OPENSSL_ALGO_MD5);

        openssl_free_key($pubRes);

        if(!$bool){
            return false;
        }
        return true;
    }

    /**
     * 解密
     * @param $data
     * @return false|string
     */
    public function aesDecrypt($data)
    {
        $data = $this->base64UrlDecode($data);

        $key = $this->base64UrlDecode($this->decryptKey);

        $decrypted = openssl_decrypt($data, "aes-128-ecb", $key, OPENSSL_RAW_DATA);

        return $decrypted;
    }

    /**
     * base64 URL安全编码
     * @param $data
     * @return string
     */
    public function encodeUrlSafeBase64($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * base64 URL安全解码
     * @param $input
     * @return false|string
     */
    public function base64UrlDecode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    private function sign($preSign)
    {
        // 将私钥转换为PEM格式
        $privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n";
        $privateKeyPEM .= chunk_split($this->privateKey, 64, "\n");
        $privateKeyPEM .= "-----END PRIVATE KEY-----\n";

        $priRes = openssl_get_privatekey($privateKeyPEM);
        // 使用 RSA 签名
        openssl_sign($preSign, $signature, $priRes, OPENSSL_ALGO_MD5);

        //释放资源
        openssl_free_key($priRes);

        // 将签名编码为 URL 安全的 BASE64
        return $signature;
    }

    private function getMillisecond()
    {
        // 获取当前时间戳（秒和微秒）
        $timestamp = microtime(true);
        // 转换为毫秒
        return (int)($timestamp * 1000);
    }

    private function aesEncrypt($data)
    {
        $secretKey = $this->base64UrlDecode($this->decryptKey);

        // 加密
        $encrypted = openssl_encrypt($data, "aes-128-ecb", $secretKey, OPENSSL_RAW_DATA);

        return $encrypted;
    }

    private function getHttpClient()
    {
        if(!$this->client){
            return new Client(['base_uri' => $this->host]);
        }
        return $this->client;
    }

}