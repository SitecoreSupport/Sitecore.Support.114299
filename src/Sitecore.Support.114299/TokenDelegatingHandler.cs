using Sitecore.Services.Core.Diagnostics;
using Sitecore.Services.Core.Security;
using Sitecore.Services.Infrastructure.Sitecore.Security;
using Sitecore.Services.Infrastructure.Web.Http.Security;
using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Sitecore.Support.Services.Infrastructure.Sitecore.Security
{
  public class TokenDelegatingHandler : DelegatingHandler
  {
    private readonly ITokenProvider _tokenProvider;
    private readonly IUserService _userService;

    private static readonly BindingFlags _bFlags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;

    public TokenDelegatingHandler()
      : this(new ConfiguredOrNullTokenProvider(new SigningTokenProvider()), new UserService())
    {
    }

    protected TokenDelegatingHandler(ITokenProvider tokenProvider, IUserService userService)
    {
      this._tokenProvider = tokenProvider;
      this._userService = userService;
    }

    protected TokenDelegatingHandler(HttpMessageHandler innerHandler)
      : this(innerHandler, new ConfiguredOrNullTokenProvider(new SigningTokenProvider()), new UserService())
    {
    }

    protected TokenDelegatingHandler(HttpMessageHandler innerHandler, ITokenProvider tokenProvider, IUserService userService)
      : base(innerHandler)
    {
      this._tokenProvider = tokenProvider;
      this._userService = userService;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
      this.AttemptLoginWithToken(request);
      return await base.SendAsync(request, cancellationToken);
    }

    private void AttemptLoginWithToken(HttpRequestMessage request)
    {
      if (!request.Headers.Contains("token"))
        return;

      JwtSecurityTokenHandler tokenHandler = null;
      TokenValidationParameters _tokenValidationParameters = null;
      ILogger _logger = null;
      ITokenValidationResult validationResult;
      if (GetInnerProviderParams(out tokenHandler, out _tokenValidationParameters, out _logger))
      {
        validationResult = this.ValidateToken(request.Headers.GetValues("token").FirstOrDefault(), tokenHandler, _tokenValidationParameters, _logger);
      }
      else
      {
        validationResult = this._tokenProvider.ValidateToken(request.Headers.GetValues("token").FirstOrDefault<string>());
      }

      if (!validationResult.IsValid || validationResult.Claims.Where(c => c.Type == "User").Count<Claim>() != 1)
        return;
      this._userService.SwitchToUser(validationResult.Claims.First(c => c.Type == "User").Value);
    }

    protected virtual bool GetInnerProviderParams(out JwtSecurityTokenHandler tokenHandler, out TokenValidationParameters _tokenValidationParameters,
      out ILogger _logger)
    {
      tokenHandler = null;
      _tokenValidationParameters = null;
      _logger = null;

      var innerTokenProviderField = this._tokenProvider.GetType().GetField("_tokenProvider", _bFlags);
      if (innerTokenProviderField != null)
      {
        var innerTokenProvider = innerTokenProviderField.GetValue(this._tokenProvider) as SigningTokenProvider;
        if (innerTokenProvider != null)
        {
          var tokenHandlerField = innerTokenProvider.GetType().GetField("tokenHandler", _bFlags);
          if (tokenHandlerField != null)
          {
            tokenHandler = tokenHandlerField.GetValue(innerTokenProvider) as JwtSecurityTokenHandler;
            if (tokenHandler != null)
            {
              var _tokenValidationParametersField = innerTokenProvider.GetType().GetField("_tokenValidationParameters", _bFlags);
              if (_tokenValidationParametersField != null)
              {
                _tokenValidationParameters = _tokenValidationParametersField.GetValue(innerTokenProvider) as TokenValidationParameters;
                if (_tokenValidationParameters != null)
                {
                  var _loggerField = innerTokenProvider.GetType().GetField("_logger", _bFlags);
                  if (_loggerField != null)
                  {
                    _logger = _loggerField.GetValue(innerTokenProvider) as ILogger;
                  }
                }
              }
            }
          }
        }
      }
      return ((tokenHandler != null) && (_tokenValidationParameters != null) && (_logger != null));
    }    

    public ITokenValidationResult ValidateToken(string token, JwtSecurityTokenHandler tokenHandler, TokenValidationParameters _tokenValidationParameters,
      ILogger _logger)
    {
      try
      {
        SecurityToken token2;
        ClaimsPrincipal principal = tokenHandler.ValidateToken(token, _tokenValidationParameters, out token2);
        return new ValidatedToken
        {
          Claims = principal.Claims,
          IsValid = true
        };
      }
      catch (SecurityTokenInvalidLifetimeException exception)
      {
        string message = exception.ToString().Replace("{", "{{").Replace("}", "}}");
        _logger.Debug(string.Format("Token invalid: {0}", message), new object[] { this });
      }
      catch (SecurityTokenValidationException exception2)
      {
        _logger.Debug(string.Format("Token invalid: {0}", exception2), new object[] { this });
      }
      catch (Exception exception3)
      {
        _logger.Error("Unable to validate token", new object[] { exception3 });
      }
      return new ValidatedToken { IsValid = false };
    }


  }
}