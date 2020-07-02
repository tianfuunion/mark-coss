<?php

namespace mark\coss\core\response;

interface CossResponseInterface {

    public function getResponse($status, $reason, $result);

}