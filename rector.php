<?php
use Rector\Hyperf\Set\HyperfSetList;
use Rector\Config\RectorConfig;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->sets([
        HyperfSetList::HYPERF_31
    ]);
};