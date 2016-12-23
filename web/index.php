<?php

use Silex\Application as SilexApplication;
use Igorw\Silex\ConfigServiceProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use AgentSIB\Diadoc\Model\OpensslSignerProvider;
use AgentSIB\Diadoc\Exception\SignerProviderException;

require __DIR__.'/../vendor/autoload.php';

$app = new SilexApplication();

$app['diadoc_signer'] = $app->share(function(SilexApplication $app){
    return new OpensslSignerProvider(
        $app['ca_file'],
        $app['cert_file'],
        $app['key_file'],
        $app['openssl_bin']
    );
});


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

    $result = $app['diadoc_signer']->sign(base64_decode($request->request->get('data')));

    return base64_encode($result);
});

$app->post('/decrypt', function(Request $request) use ($app) {

    $result = $app['diadoc_signer']->decrypt(base64_decode($request->request->get('data')));

    return base64_encode($result);
});

$app->post('/encrypt', function(Request $request) use ($app) {

    $result = $app['diadoc_signer']->encrypt(base64_decode($request->request->get('data')));

    return base64_encode($result);
});

$app->post('/checkSign', function(Request $request) use ($app) {

    $result = $app['diadoc_signer']->checkSign(
        base64_decode($request->request->get('data')),
        base64_decode($request->request->get('sign'))
    );

    return $result?'true':'false';
});

$app->error(function (SignerProviderException $e) {
    return new Response($e->getMessage(), Response::HTTP_BAD_REQUEST);
});

$app->error(function(\Exception $e){
    return $e->getMessage();
});


$app->run();