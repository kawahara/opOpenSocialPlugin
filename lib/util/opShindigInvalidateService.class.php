<?php

class opShindigInvalidateService implements InvalidateService
{
  protected
    $invalidationEntry,
    $cache;

  protected static
    $marker = null,
    $makerCache = null,
    $TOKEN_PREFIX = 'INV_TOK_';

  public function __construct(Cache $cache)
  {
    $this->cache = $cache;
    $this->invalidationEntry = Cache::createCache(Shindig_Config::get('data_cache'), 'InvalidationEntry');
    if (self::$makerCache == null) {
      self::$makerCache = Cache::createCache(Shindig_Config::get('data_cache'), 'MarkerCache');
      $value = self::$makerCache->expiredGet('marker');
      if ($value['found'])
      {
        self::$marker = $value['data'];
      }
      else
      {
        self::$marker = 0;
        self::$makerCache->set('marker', self::$marker);
      }
    }
  }

  public function invalidateApplicationResources(array $uris, SecurityToken $token)
  {
    foreach ($uris as $uri)
    {
      $request = new RemoteContentRequest($uri);
      $this->cache->invalidate($request->toHash());

      // GET
      $request = new RemoteContentRequest($uri);
      $request->createRemoteContentRequestWithUri($uri);
      $this->cache->invalidate($request->toHash());

      // GET & SIGNED
      $request = new RemoteContentRequest($uri);
      $request->setAuthType(RemoteContentRequest::$AUTH_SIGNED);
      $request->setNotSignedUri($uri);
      $this->cache->invalidate($request->toHash());
    }

    if (Doctrine::getTable('SnsConfig')->get('is_use_outer_shindig', false))
    {
      require_once 'OAuth.php';

      $shindigUrl = Doctrine::getTable('SnsConfig')->get('shindig_url');
      if (substr($shindigUrl, -1) !== '/')
      {
        $shindigUrl .= '/';
      }

      $invalidateUrl = $shindigUrl.'gadgets/api/rest/cache';

      $key    = Doctrine::getTable('SnsConfig')->get('shindig_backend_key');
      $secret = Doctrine::getTable('SnsConfig')->get('shindig_backend_secret');
      $consumer = new OAuthConsumer($key, $secret);
      $oauthRequest = OAuthRequest::from_consumer_and_token(
        $consumer,
        null,
        'POST',
        $invalidateUrl
      );
      $oauthRequest->set_parameter('xoauth_requestor_id', 1);
      $oauthRequest->sign_request(new OAuthSignatureMethod_HMAC_SHA1(), $consumer, null);
      $request = new RemoteContentRequest($invalidateUrl.'?xoauth_requestor_id=1');
      $request->setMethod('POST');
      $request->setContentType('application/json');
      $request->setPostBody(json_encode( array('invalidationKeys' => $uris)));
      $request->setHeaders($oauthRequest->to_header());
      $request->getOptions()->ignoreCache = true;
      $remoteContent = Shindig_Config::get('remote_content');
      $fetcher = new $remoteContent();
      $fetcher->fetch($request);
    }
  }

  public function invalidateUserResources(array $opensocialIds, SecurityToken $token)
  {
    foreach ($opensocialIds as $opensocialId)
    {
      ++self::$marker;
      self::$makerCache->set('marker', self::$marker);
      $this->invalidationEntry->set($this->getKey($opensocialId, $token), self::$marker);
    }
  }

  public function isValid(RemoteContentRequest $request)
  {
    if ($request->getAuthType() == RemoteContentRequest::$AUTH_NONE)
    {
      return true;
    }

    return $request->getInvalidation() == $this->getInvalidationMark($request);
  }

  public function markResponse(RemoteContentRequest $request)
  {
    $mark = $this->getInvalidationMark($request);
    if ($mark)
    {
      $request->setInvalidation($mark);
    }
  }

  protected function getKey($userId, SecurityToken $token)
  {
    $pos = strrpos($userId, ':');
    if ($pos !== false)
    {
      $userId = substr($userId, $pos + 1);
    }

    if ($token->getAppId())
    {

      return self::$TOKEN_PREFIX . $token->getAppId() . '_' . $userId;
    }

    return self::$TOKEN_PREFIX . $token->getAppUrl() . '_' . $userId;
  }

  protected function getInvalidationMark(RemoteContentRequest $request)
  {
    $token = $request->getToken();
    if (!$token)
    {
      return null;
    }

    $currentInvalidation = '';
    if ($token->getOwnerId())
    {
      $ownerKey = $this->getKey($token->getOwnerId(), $token);
      $cached = $this->invalidationEntry->expiredGet($ownerKey);
      $ownerStamp = $cached['found'] ? $cached['data'] : false;
    }
    if ($token->getViewerId())
    {
      $viewerKey = $this->getKey($token->getViewerId(), $token);
      $cached = $this->invalidationEntry->expiredGet($viewerKey);
      $viewerStamp = $cached['found'] ? $cached['data'] : false;
    }
    if (isset($ownerStamp))
    {
      $currentInvalidation = $currentInvalidation . 'o=' . $ownerStamp . ';'; 
    }
    if (isset($viewerStamp))
    {
      $currentInvalidation = $currentInvalidation . 'v=' . $viewerStamp . ';'; 
    }

    return $currentInvalidation;
  }
}
