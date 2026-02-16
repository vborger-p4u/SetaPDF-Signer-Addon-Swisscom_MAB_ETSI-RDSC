<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\SwisscomMabEtsiRdsc;

use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

class Client
{
    public static string $AUTH_URL = 'https://auth.trustservices.swisscom.com';
    public static string $AUTH_URL_MTLS = 'https://auth-trustservices.mtls-scapp.swisscom.com';
    public static string $SIGN_URL = 'https://ais.swisscom.com';

    public function __construct(
        protected $clientId,
        protected $secret,
        protected ClientInterface $client,
        protected RequestFactoryInterface $requestFactory,
        protected StreamFactoryInterface $streamFactory,
    ) {
    }

    /**
     * @param string $state
     * @param string $redirectUri
     * @param array $claims
     * @param array $additionalParams
     * @return string Returns the auth url for the user.
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws Exception
     */
    public function parRequest(
        string $state,
        string $nonce,
        string $redirectUri,
        array $claims,
        array $additionalParams = []
    ): string {
        $url = self::$AUTH_URL_MTLS . '/auth/realms/broker/protocol/openid-connect/ext/par/request';
        $requestData = \array_merge([
            'state' => $state,
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'client_secret' => $this->secret,
            'scope' => 'sign ident',
            'redirect_uri' => $redirectUri,
            'claims' => $claims,
        ], $additionalParams);
        
        $request = (
            $this->requestFactory->createRequest('GET', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream(json_encode($requestData, \JSON_THROW_ON_ERROR)))
        );
        $response = $this->client->sendRequest($request);
        if (
            $response->getStatusCode() !== 201
            || !str_contains($response->getHeaderLine('Content-Type'), 'application/json')
        ) {
            throw new Exception(
                'Unexpected server response (code ' . $response->getStatusCode() . '): '
                . $response->getBody()->getContents()
            );
        }

        $responseData = json_decode($response->getBody()->getContents(), true, \JSON_THROW_ON_ERROR);

        return (
            self::$AUTH_URL . '/auth/realms/broker/protocol/openid-connect/auth?'
            . http_build_query([
                'client_id' => $this->clientId,
                'request_uri' => $responseData['request_uri'],
                'state' => $state,
                'nonce' => $nonce,
            ])
        );
    }

    /**
     * @param string $code
     * @return array{access_token: string, expires_in: string, token_type: string, session_state: string, scope: string}
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws Exception
     */
    public function generateToken(string $code): array
    {
        $url = self::$AUTH_URL_MTLS . '/api/auth/realms/broker/protocol/openid-connect/token';
        $requestData = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->clientId,
            'client_secret' => $this->secret,
        ];
        $request = (
            $this->requestFactory->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream(\http_build_query($requestData)))
        );
        $response = $this->client->sendRequest($request);
        if (
            $response->getStatusCode() !== 200
            || !str_contains($response->getHeaderLine('Content-Type'), 'application/json')
        ) {
            throw new Exception(
                'Unexpected server response (code ' . $response->getStatusCode() . '): '
                . $response->getBody()->getContents()
            );
        }
        return json_decode($response->getBody()->getContents(), true, \JSON_THROW_ON_ERROR);
    }

    /**
     * @param string $sad
     * @param string $requestId
     * @param array{hashAlgorithmOID: string, hashes: string[]} $documentDigests
     * @param string $credentialId
     * @param string $conformanceLevel Supported values: AdES-B-B, AdES-B-T, AdES-B-LT, AdES-B-LTA
     * @param string $signatureFormat
     * @return array{responseID: string, signatureObject: string[], validationInfo: array{ocsp: array, crl: string[]}}
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws JsonException
     */
    public function sign(
        string $sad,
        string $requestId,
        array $documentDigests,
        string $credentialId,
        string $conformanceLevel = 'AdES-B-LT',
        string $signatureFormat = 'P'
    ): array {
        $url = self::$SIGN_URL . '/AIS-Server/etsi/standard/rdsc/v1/signatures/signDoc';
        $requestData = [
            'SAD' => $sad,
            'requestID' => $requestId,
            'credentialID' => $credentialId,
            'profile' => 'http://uri.etsi.org/19432/v1.1.1#/creationprofile#',
            'signatureFormat' => $signatureFormat,
            'conformanceLevel' => $conformanceLevel,
            'documentDigests' => $documentDigests
        ];
        $request = (
            $this->requestFactory->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream(json_encode($requestData, \JSON_THROW_ON_ERROR)))
        );
        $response = $this->client->sendRequest($request);
        if (
            $response->getStatusCode() !== 200
            || !str_contains($response->getHeaderLine('Content-Type'), 'application/json')
        ) {
            throw new Exception(
                'Unexpected server response (code ' . $response->getStatusCode() . '): '
                . $response->getBody()->getContents()
            );
        }
        return json_decode($response->getBody()->getContents(), true, \JSON_THROW_ON_ERROR);
    }
}
