#!/usr/bin/env php
<?php
error_reporting(0);
require __DIR__.'/vendor/autoload.php';

use Jcid\Console\Command\SensioLabsSecurityAdvisoriesCheckerCommand;
use Symfony\Component\Console\Application;

$application = new Application();
$application->add(new SensioLabsSecurityAdvisoriesCheckerCommand());
$application->run();
