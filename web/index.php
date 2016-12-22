<?php

use Silex\Application as SilexApplication;
use Igorw\Silex\ConfigServiceProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Process\ProcessBuilder;

require __DIR__.'/../vendor/autoload.php';

$app = new SilexApplication();

function getOpensslProcess(array $args = [], $input = null) {
    global $app;
    return ProcessBuilder::create($args)
        ->setPrefix($app['openssl_bin'])
        ->setInput($input)->getProcess();

}

$app->register(new ConfigServiceProvider(__DIR__.'/../config/config.php'));
$configFile = __DIR__.'/../config/config_local.php';
if (file_exists($configFile)) {
    $app->register(new ConfigServiceProvider(__DIR__.'/../config/config_local.php'));
}

$app->before(function(Request $request) use ($app) {
    if ($request->headers->get('X-Token', null) != $app['token']) {
        throw new AccessDeniedHttpException('Wrong token');
    }
});

$app->get('/', function(){
    return 'Hello?';
});

$app->post('/sign', function(Request $request) use ($app) {

    $process = getOpensslProcess([
        'smime',
        '-sign',
        '-binary',
        '-noattr',
        '-gost89',
        '-signer', $app['cert_file'],
        '-inkey', $app['key_file'],
        '-outform', 'der'
    ], base64_decode($request->request->get('data')));

    return base64_encode($process->mustRun()->getOutput());
});

$app->post('/decrypt', function(Request $request) use ($app) {
    $process = getOpensslProcess([
        'smime',
        '-decrypt',
        '-binary',
        '-noattr',
        '-inform', 'der',
        '-inkey', $app['key_file'],
    ], base64_decode($request->request->get('data')));

    return base64_encode($process->mustRun()->getOutput());
});

$app->post('/encrypt', function(Request $request) use ($app) {
    $process = getOpensslProcess([
        'smime',
        '-encrypt',
        '-binary',
        '-noattr',
        '-outform', 'DER',
        '-gost89',
        $app['cert_file']
    ], base64_decode($request->request->get('data')));

    return base64_encode($process->mustRun()->getOutput());
});

$app->post('/checkSign', function(Request $request) use ($app) {
    $file = tmpfile();
    $metaDatas = stream_get_meta_data($file);
    $tmpFilename = $metaDatas['uri'];
    fwrite($file, base64_decode($request->request->get('data')));

    $process = getOpensslProcess([
        'smime',
        '-verify',
        '-binary',
        '-noattr',
        '-gost89',
        '-inform', 'der',
        '-CAfile', $app['ca_file'],
        '-content', $tmpFilename
    ], base64_decode($request->request->get('sign')));

    $result = $process->run();
    fclose($file);

    return $result === 0?'true':'false';
});

$app->error(function(\Exception $e){
    return $e->getMessage();
});

$app->run();