<?php

    declare (strict_types=1);

    namespace mark\coss;

    use mark\http\Curl;
    use mark\coss\core\CossException;
    use mark\coss\core\CossUtil;
    use finfo;

    /**
     * Class Coss
     *
     * @package mark\coss
     */
    class Coss
    {

        private $file = 'file';
        private $filename; //上传的文件表单
        private $tmp_name;    //上传的临时文件名
        private $size;     //上传文件的尺寸
        private $error;

        //限制上传文件的类型,可以使用set()设置，使用小字母
        private $allowtype = array('jpg', 'gif', 'png', 'mp4', 'avi', 'rm', 'rmvb', '3pg');
        //限制文件上传大小，单位是字节,可以使用set()设置
        private $maxsize;
        //设置是否随机重命名 false为不随机,可以使用set()设置
        private $israndname = true;

        //源文件名
        private $originName;
        //临时文件名
        private $tmpFileName;
        //文件类型(文件后缀)
        private $fileType;
        //文件大小
        private $fileSize;
        //新文件名
        private $newFileName;
        //错误号
        private $errorNum = 0;
        //错误报告消息
        private $errorMess = '';
        //设置上传路径
        private $path = '/storage/';

        private $appId;
        private $appSecret;

        private $curl;

        /**
         * Coss 管理系统
         *
         * @param  $appId
         * @param  $appSecret
         * @param  $endpoint
         * @param bool $isCName
         * @param null $securityToken
         * @param null $requestProxy
         *
         * @throws CossException
         * @property int $timeout = 0;
         * @property int $validate
         * @property Curl $curl
         *
         * Coss constructor.
         *
         */
        public function __construct($appId, $appSecret, $endpoint, $isCName = false, $securityToken = null, $requestProxy = null)
        {
            $appId = trim($appId);
            $appSecret = trim($appSecret);
            $endpoint = trim(trim($endpoint), '/');

            if (empty($appId)) {
                throw new CossException('access key id is empty');
            }
            if (empty($appSecret)) {
                throw new CossException('access key secret is empty');
            }
            if (empty($endpoint)) {
                throw new CossException('endpoint is empty');
            }

            $this->curl = Curl::getInstance();
            $this->curl->upload('https://' . $endpoint . '/api.php/objects/upload');

            $this->curl->append(
                array('appid' => $appId,
                    'appsecret' => $appSecret,
                    'endpoint' => $endpoint,
                    'action' => 'upload')
            );

            self::checkEnv();
        }

        /**
         * Check if all dependent extensions are installed correctly.
         * For now only "curl" is needed.
         *
         * @throws CossException
         */
        public static function checkEnv()
        {
            if (function_exists('get_loaded_extensions')) {
                //Test curl extension
                $enabled_extension = array('curl');
                $extensions = get_loaded_extensions();
                if ($extensions) {
                    foreach ($enabled_extension as $item) {
                        if (!in_array($item, $extensions)) {
                            throw new CossException(
                                'Extension {' . $item . '} is not installed or not enabled, please check your php env.'
                            );
                        }
                    }
                } else {
                    throw new CossException('function get_loaded_extensions not found.');
                }
            } else {
                throw new CossException('Function get_loaded_extensions has been disabled, please check php config.');
            }
        }

        /**
         * 用于设置成员属性（$path, $allowtype,$maxsize, $israndname, $thumb,$watermark）
         * 可以通过连贯操作一次设置多个属性值
         *
         * @param string $key 成员属性名(不区分大小写)
         * @param mixed $val 为成员属性设置的值
         *
         * @return    object 返回自己对象$this
         */
        public function set($key, $val)
        {
            $key = strtolower($key);
            if (array_key_exists($key, get_class_vars(get_class($this)))) {

                // $this->setOption($key, $val);
                $this->$key = $val;
            }

            return $this;
        }

        /**
         * 调用该方法上传文件
         *
         * @param $file
         *
         * @return $this
         */
        public function upload($file)
        {
            $this->curl->appendFile($file);

            return $this;
        }

        /**
         * Uploads a local file
         *
         * @param string $bucket bucket name
         * @param string $object object name
         * @param string $file
         * @param null $options
         *
         * 参考AliYun OssClient
         * public function uploadFile($bucket, $object, $file, $options = null)
         *
         * @throws CossException
         * @deprecated 有待验证
         */
        public function putFile(string $bucket, string $object, string $file, $options = null)
        {
            $this->curl->append(array('bucket' => $bucket));

            // $this->curl->push("object", $object);

            if (!file_exists(dirname($file))) {
                throw new CossException($file . ' file does not exist');
            }

            $this->curl->appendFile($file);
            $this->curl->appendFile($object);

            if ($options != null) {
                if (is_array($options)) {
                    $this->curl->append($options);
                }

                $options['content_md5'] = md5_file(dirname($file));
                $options = array_merge(pathinfo($file), $options);

                $this->curl->append(array('callback_' . $options['content_md5'] => json_encode($options)));
            }

        }

        private $object;

        /**
         * 普通文件上传
         *
         * @param      $bucket
         * @param      $object
         * @param      $file
         * @param null $options
         *
         * @return $this
         */
        public function uploadFile($bucket, $object, $file, $options = null)
        {
            if (file_exists(realpath($file))) {
                $this->curl->appendFile($file);

                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mime = $finfo->file(realpath($file));

                $HTTP_DATA = array(
                    Coss::COSS_BUCKET => $bucket,
                    Coss::COSS_OBJECT => $object,
                    Coss::COSS_BASENAME => $object,

                    'filemime' => $mime,
                    'filesize' => filesize(realpath($file)),
                    'md5' => md5(realpath($file)),
                    'sha1' => sha1(realpath($file)),

                    'md5_b' => md5(basename($file)),
                    'sha1_b' => sha1(basename($file)),

                    'md5_file' => md5_file(realpath($file)),
                    'sha1_file' => sha1_file(realpath($file)),
                );
                if ($options != null) {
                    $HTTP_DATA = array_merge($HTTP_DATA, $options);
                }

                $HTTP_DATA = array_merge(pathinfo($file), $HTTP_DATA);

                $this->curl->appendData(md5_file(realpath($file)), json_encode($HTTP_DATA));
            }

            return $this;
        }

        /**
         * 上传文件的表单名称 例如：<input type="file" name="myfile"> 参数则为myfile
         *
         * @param string $name
         *
         * @return $this
         */
        public function putInputFiles($name = '')
        {
            if ($name != '') {

            }

            return $this;
        }

        /**
         *
         */
        public function MultiPart()
        {
        }

        /**
         * @param string $type
         *
         * @return array|bool|false|mixed|string
         */
        public function execute($type = 'json')
        {
            $result = $this->curl->execute();
            if ($result) {
                if ($type === 'json') {
                    return $result;
                }

                return json_decode($result, true);
            }

            return $this->curl->getError();
        }

        /**
         * 获取上传后的文件名称
         *
         * @return mixed  上传后，新文件的名称
         */
        public function getFileName()
        {
            return $this->newFileName;
        }

        public function getInfo()
        {
            return $this->curl->getInfo();
        }

        /**
         * 上传失败后，调用该方法则返回，上传出错信息
         *
         *
         * @return    string     返回上传文件出错的信息提示
         */
        public function getErrorMsg()
        {
            return $this->errorMess;
        }

        /**
         * 设置上传出错信息
         *
         * @return string
         */
        private function getError()
        {
            $str = "上传文件{$this->originName}时出错";
            switch ($this->errorNum) {
                case 4:
                    $str .= '没有文件被上传';
                    break;
                case 3:
                    $str .= '文件只有部分被上传';
                    break;
                case 2:
                    $str .= '上传文件的大小超过了 HTML 表单中 MAX_FILE_SIZE 选项指定的值';
                    break;
                case 1:
                    $str .= '上传的文件超过了 php.ini 中 upload_max_filesize 选项限制的值';
                    break;
                case -1:
                    $str .= '未允许类型';
                    break;
                case -2:
                    $str .= "文件过大,上传的文件不能超过{$this->maxsize}个字节";
                    break;
                case -3:
                    $str .= '上传失败';
                    break;
                case -4:
                    $str .= '建立存放上传文件目录失败，请重新指定上传目录';
                    break;
                case -5:
                    $str .= '必须指定上传文件的路径';
                    break;
                default:
                    $str .= '未知错误';
            }

            return $str . '<br>';
        }

        /**
         * 设置和$_FILES有关的内容
         *
         * @param string $name
         * @param string $tmp_name
         * @param int $size
         * @param int $error
         *
         * @return bool
         */
        private function setFiles($name = '', $tmp_name = '', $size = 0, $error = 0)
        {
            $this->setOption('errorNum', $error);
            if ($error) {
                return false;
            }
            $this->setOption('originName', $name);
            $this->setOption('tmpFileName', $tmp_name);
            $aryStr = explode('.', $name);
            $this->setOption('fileType', strtolower($aryStr[count($aryStr) - 1]));
            $this->setOption('fileSize', $size);

            return true;
        }

        /**
         * 为单个成员属性设置值
         *
         * @param $key
         * @param $val
         */
        private function setOption($key, $val)
        {
            $this->$key = $val;
        }

        /**
         * 设置上传后的文件名称
         */
        private function setNewFileName()
        {
            if ($this->israndname) {
                $this->setOption('newFileName', $this->proRandName());
            } else {
                $this->setOption('newFileName', $this->originName);
            }
        }

        /**
         * 检查上传的文件是否是合法的类型
         *
         * @return bool
         */
        private function checkFileType()
        {
            if (in_array(strtolower($this->fileType), $this->allowtype)) {
                return true;
            }

            $this->setOption('errorNum', -1);

            return false;
        }

        /**
         * 检查上传的文件是否是允许的大小
         *
         * @return bool
         */
        private function checkFileSize()
        {
            if ($this->fileSize > $this->maxsize) {
                $this->setOption('errorNum', -2);

                return false;
            }

            return true;
        }

        /**
         * 检查是否有存放上传文件的目录
         *
         * @return bool
         */
        private function checkFilePath()
        {
            if (empty($this->path)) {
                $this->setOption('errorNum', -5);

                return false;
            }
            if (!file_exists($this->path) || !is_writable($this->path)) {
                if (!mkdir($concurrentDirectory = $this->path, 0755) && !is_dir($concurrentDirectory)) {
                    $this->setOption('errorNum', -4);

                    return false;
                }
            }

            return true;
        }

        /**
         * 设置随机文件名
         *
         * @return string
         */
        private function proRandName()
        {
            $fileName = date('YmdHis') . '_' . rand(1000, 9999);    //获取随机文件名

            return $fileName . '.' . $this->fileType;     //返回文件名加原扩展名
        }

        /**
         * 复制上传文件到指定的位置
         *
         * @return bool
         */
        private function copyFile()
        {
            if (!$this->errorNum) {
                $path = rtrim($this->path, '/') . '/';
                $path .= $this->newFileName;
                if (@move_uploaded_file($this->tmpFileName, $path)) {
                    return true;
                }

                $this->setOption('errorNum', -3);

                return false;
            }

            return false;
        }

        // Constants for Life cycle
        public const COSS_LIFECYCLE_EXPIRATION = 'Expiration';

        public const COSS_LIFECYCLE_TIMING_DAYS = 'Days';

        public const COSS_LIFECYCLE_TIMING_DATE = 'Date';

        //OSS Internal constants
        public const COSS_BUCKET = 'bucket';

        public const COSS_OBJECT = 'object';

        public const COSS_HEADERS = CossUtil::COSS_HEADERS;

        public const COSS_METHOD = 'method';

        public const COSS_QUERY = 'query';

        public const COSS_BASENAME = 'basename';

        public const COSS_MAX_KEYS = 'max-keys';

        public const COSS_UPLOAD_ID = 'uploadId';

        public const COSS_PART_NUM = 'partNumber';

        public const COSS_COMP = 'comp';

        public const COSS_LIVE_CHANNEL_STATUS = 'status';

        public const COSS_LIVE_CHANNEL_START_TIME = 'startTime';

        public const COSS_LIVE_CHANNEL_END_TIME = 'endTime';

        public const COSS_POSITION = 'position';

        public const COSS_MAX_KEYS_VALUE = 100;

        public const COSS_MAX_OBJECT_GROUP_VALUE = CossUtil::COSS_MAX_OBJECT_GROUP_VALUE;

        public const COSS_MAX_PART_SIZE = CossUtil::COSS_MAX_PART_SIZE;

        public const COSS_MID_PART_SIZE = CossUtil::COSS_MID_PART_SIZE;

        public const COSS_MIN_PART_SIZE = CossUtil::COSS_MIN_PART_SIZE;

        public const COSS_FILE_SLICE_SIZE = 8192;

        public const COSS_PREFIX = 'prefix';

        public const COSS_SUFFIX = 'suffix';

        public const COSS_DELIMITER = 'delimiter';

        public const COSS_MARKER = 'marker';

        public const COSS_ACCEPT_ENCODING = 'Accept-Encoding';

        public const COSS_CONTENT_MD5 = 'Content-Md5';

        public const COSS_SELF_CONTENT_MD5 = 'x-coss-meta-md5';

        public const COSS_CONTENT_TYPE = 'Content-Type';

        public const COSS_CONTENT_LENGTH = 'Content-Length';

        public const COSS_IF_MODIFIED_SINCE = 'If-Modified-Since';

        public const COSS_IF_UNMODIFIED_SINCE = 'If-Unmodified-Since';

        public const COSS_IF_MATCH = 'If-Match';

        public const COSS_IF_NONE_MATCH = 'If-None-Match';

        public const COSS_CACHE_CONTROL = 'Cache-Control';

        public const COSS_EXPIRES = 'Expires';

        public const COSS_PREAUTH = 'preauth';

        public const COSS_CONTENT_COING = 'Content-Coding';

        public const COSS_CONTENT_DISPOSTION = 'Content-Disposition';

        public const COSS_RANGE = 'range';

        public const COSS_ETAG = 'etag';

        public const COSS_LAST_MODIFIED = 'lastmodified';

        public const OS_CONTENT_RANGE = 'Content-Range';

        public const COSS_CONTENT = CossUtil::COSS_CONTENT;

        public const COSS_BODY = 'body';

        public const COSS_LENGTH = CossUtil::COSS_LENGTH;

        public const COSS_HOST = 'Host';

        public const COSS_DATE = 'Date';

        public const COSS_AUTHORIZATION = 'Authorization';

        public const COSS_FILE_DOWNLOAD = 'fileDownload';

        public const COSS_FILE_UPLOAD = 'fileUpload';

        public const COSS_PART_SIZE = 'partSize';

        public const COSS_SEEK_TO = 'seekTo';

        public const COSS_SIZE = 'size';

        public const COSS_QUERY_STRING = 'query_string';

        public const COSS_SUB_RESOURCE = 'sub_resource';

        public const COSS_DEFAULT_PREFIX = 'x-coss-';

        public const COSS_CHECK_MD5 = 'checkmd5';

        public const DEFAULT_CONTENT_TYPE = 'application/octet-stream';

        public const COSS_SYMLINK_TARGET = 'x-coss-symlink-target';

        public const COSS_SYMLINK = 'symlink';

        public const COSS_HTTP_CODE = 'http_code';

        public const COSS_REQUEST_ID = 'x-coss-request-id';

        public const COSS_INFO = 'info';

        public const COSS_STORAGE = 'storage';

        public const COSS_RESTORE = 'restore';

        public const COSS_STORAGE_STANDARD = 'Standard';

        public const COSS_STORAGE_IA = 'IA';

        public const COSS_STORAGE_ARCHIVE = 'Archive';

        //private URLs
        public const COSS_URL_ACCESS_KEY_ID = 'OSSAccessKeyId';

        public const COSS_URL_EXPIRES = 'Expires';

        public const COSS_URL_SIGNATURE = 'Signature';

        //HTTP METHOD
        public const COSS_HTTP_GET = 'GET';

        public const COSS_HTTP_PUT = 'PUT';

        public const COSS_HTTP_HEAD = 'HEAD';

        public const COSS_HTTP_POST = 'POST';

        public const COSS_HTTP_DELETE = 'DELETE';

        public const COSS_HTTP_OPTIONS = 'OPTIONS';

        //Others
        public const COSS_ACL = 'x-coss-acl';

        public const COSS_OBJECT_ACL = 'x-coss-object-acl';

        public const COSS_OBJECT_GROUP = 'x-coss-file-group';

        public const COSS_MULTI_PART = 'uploads';

        public const COSS_MULTI_DELETE = 'delete';

        public const COSS_OBJECT_COPY_SOURCE = 'x-coss-copy-source';

        public const COSS_OBJECT_COPY_SOURCE_RANGE = 'x-coss-copy-source-range';

        public const COSS_OBJECT_PATH = 'object_path';

        public const COSS_OBJECT_FOLDERID = 'folderid';

        public const COSS_PROCESS = 'x-coss-process';

        public const COSS_CALLBACK = 'x-coss-callback';

        public const COSS_CALLBACK_VAR = 'x-coss-callback-var';

        //Constants for STS SecurityToken
        public const COSS_SECURITY_TOKEN = 'x-coss-security-token';

        public const COSS_ACL_TYPE_PRIVATE = 'private';

        public const COSS_ACL_TYPE_PUBLIC_READ = 'public-read';

        public const COSS_ACL_TYPE_PUBLIC_READ_WRITE = 'public-read-write';

        public const COSS_ENCODING_TYPE = 'encoding-type';

        public const COSS_ENCODING_TYPE_URL = 'url';

        // Domain Types
        public const COSS_HOST_TYPE_NORMAL = 'normal';//http://bucket.oss-cn-hangzhou.aliyuncs.com/object

        public const COSS_HOST_TYPE_IP = 'ip';  //http://1.1.1.1/bucket/object

        public const COSS_HOST_TYPE_SPECIAL = 'special'; //http://bucket.guizhou.gov/object

        public const COSS_HOST_TYPE_CNAME = 'cname';  //http://mydomain.com/object

        //OSS ACL array
        public static $COSS_ACL_TYPES = array(
            self::COSS_ACL_TYPE_PRIVATE,
            self::COSS_ACL_TYPE_PUBLIC_READ,
            self::COSS_ACL_TYPE_PUBLIC_READ_WRITE
        );

        // CossClient version information
        public const COSS_NAME = 'tianfuunion-sdk-php';

        public const COSS_VERSION = '2.3.1';

        public const COSS_BUILD = '20200703';

        public const COSS_AUTHOR = '';

        public const COSS_OPTIONS_ORIGIN = 'Origin';

        public const COSS_OPTIONS_REQUEST_METHOD = 'Access-Control-Request-Method';

        public const COSS_OPTIONS_REQUEST_HEADERS = 'Access-Control-Request-Headers';

        //use ssl flag
        private $useSSL = false;
        private $maxRetries = 3;
        private $redirects = 0;

        // user's domain type. It could be one of the four: COSS_HOST_TYPE_NORMAL, COSS_HOST_TYPE_IP, COSS_HOST_TYPE_SPECIAL, COSS_HOST_TYPE_CNAME
        private $hostType = self::COSS_HOST_TYPE_NORMAL;
        private $requestUrl;
        private $requestProxy;
        private $accessKeyId;
        private $accessKeySecret;
        private $hostname;
        private $securityToken;
        private $enableStsInUrl = false;
        private $timeout = 0;
        private $connectTimeout = 0;
    }