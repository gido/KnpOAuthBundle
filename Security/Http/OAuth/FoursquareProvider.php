<?php

/*
 * This file is part of the KnpOAuthBundle package.
 *
 * (c) KnpLabs <hello@knplabs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Knp\Bundle\OAuthBundle\Security\Http\OAuth;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * FoursquareProvider
 *
 * @author Gilles Doge <gilles.doge@gmail.com>
 */
class FoursquareProvider extends OAuthProvider
{
    /**
     * {@inheritDoc}
     */
    protected $options = array(
        'authorization_url' => 'https://foursquare.com/oauth2/authorize',
        'access_token_url'  => 'https://foursquare.com/oauth2/access_token',
        'infos_url'         => 'https://api.foursquare.com/v2/users/self',
        'username_path'     => 'response.user.contact.email',
        'scope'             => null,
    );
    
    /**
     * {@inheritDoc}
     */
    public function getUsername($accessToken)
    {
        if ($this->getOption('infos_url') === null) {
            return $accessToken;
        }
        
        // Foursquare require to pass the OAuth token as 'oauth_token' instead of 'access_token'
        $url = $this->getOption('infos_url').'?'.http_build_query(array(
            'oauth_token' => $accessToken
        ));
        
        $userInfos    = json_decode($this->httpRequest($url), true);
        $usernamePath = explode('.', $this->getOption('username_path'));

        $username     = $userInfos;

        foreach ($usernamePath as $path) {
            if (!array_key_exists($path, $username)) {
                throw new AuthenticationException(sprintf('Could not follow username path "%s" in OAuth provider response: %s', $this->getOption('username_path'), var_export($userInfos, true)));
            }
            $username = $username[$path];
        }

        return $username;
    }
    
    /**
     * {@inheritDoc}
     */
    public function getAccessToken(Request $request, array $extraParameters = array())
    {
        $parameters = array_merge($extraParameters, array(
            'code'          => $request->get('code'),
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->getOption('client_id'),
            'client_secret' => $this->getOption('secret'),
            'redirect_uri'  => $this->getRedirectUri($request),
        ));

        $url = $this->getOption('access_token_url').'?'.http_build_query($parameters);

        $response = $this->httpRequest($url);
        $response = json_decode($response, true);
        
        if (isset($response['meta']['errorType'])) {
            $errorMessage = isset($response['meta']['errorMessage']) ?: $response['meta']['errorMessage'];
            throw new AuthenticationException(sprintf('OAuth error: %s "%s"', $response['meta']['errorType'], $errorMessage));
        }
        
        return $response['access_token'];
    }
}