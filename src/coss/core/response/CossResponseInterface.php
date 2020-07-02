<?php
    declare (strict_types=1);

    namespace mark\coss\core\response;

    interface CossResponseInterface
    {

        public function getResponse($status, $reason, $result);

    }