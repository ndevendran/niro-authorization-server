package authserver.controllers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriComponentsBuilder;

import authserver.AccessToken;
import authserver.AuthorizationRequest;
import authserver.LoginRequest;
import authserver.RefreshToken;
import authserver.User;
import authserver.data.AccessTokenRepo;
import authserver.data.AuthorizationRequestRepository;
import authserver.data.RefreshTokenRepo;
import authserver.data.UserRepository;

@Controller
@RequestMapping(path="/", produces="application/json")
public class UserController {
	public HashMap<String, String> authRequest(){
		return new HashMap<>();
	}
	
	@Autowired
	private UserRepository userRepo;
	private AccessTokenRepo tokenRepo;
	private RefreshTokenRepo refreshRepo;
	private AuthorizationRequestRepository authRepo;
	
	private ArrayList<HashMap<String, String>> clients;
	public UserController(UserRepository userRepo, 
			AccessTokenRepo tokenRepo, AuthorizationRequestRepository authRepo,
			RefreshTokenRepo refreshRepo) {
		this.userRepo = userRepo;
		this.tokenRepo = tokenRepo;
		this.authRepo = authRepo;
		this.refreshRepo = refreshRepo;
		this.clients = new ArrayList<>();
		new HashMap<>();
		addClient("oauth-client-1", "oauth-secret-1", "localhost/callback");
	}
	
	private void addClient(String clientId, String clientSecret, String redirectUri) {
		HashMap<String,String> newClient = new HashMap<String,String>();
		newClient.put("clientId", clientId);
		newClient.put("clientSecret", clientSecret);
		newClient.put("redirectUri", redirectUri);
		newClient.put("scope", "read update");
		if(this.clients == null) {
			this.clients = new ArrayList<>();
		}
		this.clients.add(newClient);	
	}
	
	private HashMap<String, String> searchClientsByClientId(String clientId, ArrayList<HashMap<String, String>> clientList){
		for (int i = 0; i < clientList.size(); i++) {
			if(clientList.get(i).get("clientId").equals(clientId)) {
				return clientList.get(i);
			}
		}
		return null;
	}
	
	private String generateRandomString(int maxLength) {
		String alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		StringBuilder randomString = new StringBuilder();
		Random randomNumber = new Random();
		while (randomString.length() < maxLength ) {
			int index = (int) (randomNumber.nextFloat() * alphanumeric.length());
			randomString.append(alphanumeric.charAt(index));
		}
		return randomString.toString();
	}
	
	private HashMap<String, String> decodeClientCredentials(List<String> auth) {
		String[] authString = auth.get(0).split(":");
		HashMap<String, String> clientCredentials = new HashMap<>();
		String clientId = Base64.getDecoder().decode(authString[0]).toString();
		String clientSecret = Base64.getDecoder().decode(authString[1]).toString();
		clientCredentials.put("clientId", clientId);
		clientCredentials.put("clientSecret", clientSecret);
		return clientCredentials;
	}
	
	@ResponseBody
	@PostMapping("/user")
	public User createUser(@RequestBody User user) {
		user.setCreatedAt(new Date());
		User savedUser = userRepo.save(user);
		return savedUser;
	}
	
	@GetMapping("/authorize")
	public String requestAuthorization(
				@RequestParam String clientId,
				@RequestParam String redirectUri,
				@RequestParam(required = false) String scope,
				Model model
			) {
		//HashMap<String, String> client = this.clients.get(0);
		HashMap<String, String> client = searchClientsByClientId(clientId, this.clients);
		if(client == null) {
			model.addAttribute("error", "Invalid client info");
			return "error";
		} else if (!client.get("redirectUri").equals(redirectUri)){
			model.addAttribute("error", "Invalid client info");
			return "error";
		}
		
		AuthorizationRequest req = new AuthorizationRequest();
		req.setClientId(clientId);
		req.setRedirectUri(redirectUri);
		
		if(scope != null) {
			String[] rscope = scope.split(" ");
			List<String> cscope = Arrays.asList(client.get("scope").split(" "));
			for(int i = 0; i < rscope.length; i++) {
				if(!cscope.contains(rscope[i])) {
					model.addAttribute("error", "Invalid scope");
					return "error";
				}
			}
			model.addAttribute("rscope", rscope);
			req.setScope(String.join(" ", rscope));
		} else {
			req.setScope(null);
		}



		String requestKey = this.authRepo.save(req).getId().toString();
		model.addAttribute("reqid", requestKey);
		
		return "approve";		
	}
	
	@PostMapping("/approve")
	public String approveAuthorization(@RequestBody LoginRequest req,
			Model model
			) {
		String username = req.getUsername();
		String password = req.getPassword();
		List<String> authScopes = req.getScopes();
		String uriWithParams;
		User user = userRepo.findByUsername(username);
		String requestKey = req.getReqid();
		
		Optional<AuthorizationRequest> sessionRequest = authRepo.findById(Long.parseLong(requestKey));
		AuthorizationRequest authRequest = sessionRequest.get();
		if(authRequest == null) {
			model.addAttribute("error", "Invalid session");
			return "error";
		}
		
		authRepo.deleteById(Long.parseLong(requestKey));
		String redirectUri = authRequest.getRedirectUri();
		String rscopeArray = authRequest.getScope();
		List<String> rscopes = (rscopeArray != null) ? Arrays.asList(rscopeArray.split(" ")) : null;
		boolean validScopes = true;
		
		if(authScopes != null && rscopes != null) {
			for(int i = 0; i<authScopes.size(); i++) {
				if(!rscopes.contains(authScopes.get(i))) {
					validScopes = false;
					break;
				}
			}
		} else if(authScopes != null && rscopes == null) {
			validScopes = false;
		}
		
		if(user.getPassword().equals(password) && validScopes) {
			if(req.getResponseType() != null) {
				if(req.getResponseType().equals("code")) {
					if(authScopes != null) {
						authRequest.setScope(String.join(" ", authScopes));
					}
					
					String code = authRepo.save(authRequest).getId().toString();
					String state = req.getState();
					uriWithParams = UriComponentsBuilder
							.fromUriString(redirectUri)
							.query("code="+code)
							.query("state="+state).build()
							.encode().toUriString();
				}
				else if(req.getResponseType().equals("token")) {
					String accessToken = this.generateRandomString(18);
					AccessToken token = new AccessToken();
					token.setAccessToken(accessToken);
					token.setCreatedAt(new Date());
					if(authScopes != null) {
						token.setScope(String.join(" ", authScopes));
					}
					
					tokenRepo.save(token);
					UriComponentsBuilder uriComponent = UriComponentsBuilder
							.fromUriString(redirectUri)
							.query("token="+accessToken);
					String state = req.getState();
					if(state != null) {
						uriComponent.query("state="+state);
					}
					
					uriWithParams = uriComponent.build().encode().toUriString();
				}
				else {
					uriWithParams = UriComponentsBuilder
							.fromUriString(redirectUri)
							.query("error=invalid_response_type")
							.build().encode().toUriString();
				}
			} else {
				uriWithParams = UriComponentsBuilder
						.fromUriString(redirectUri)
						.query("error=invalid_response_type")
						.build().encode().toUriString();
			}
		} else {
			uriWithParams = UriComponentsBuilder
					.fromUriString(redirectUri)
					.query("error=access_denied")
					.build().encode().toUriString();
			
		}
		
		return "redirect:"+uriWithParams;
	}
	
	@ResponseBody
	@GetMapping("/token")
	public ResponseEntity<HashMap<String, String>> requestToken(
			@RequestHeader("authorization") List<String> auth,
			@RequestBody AuthorizationRequest request,
			Model model
			) throws IOException{
		String clientId = null;
		String clientSecret = null;
		HashMap<String,String> response = new HashMap<>();
		
		//get auth credentials and parse JSON body
		if(auth != null && auth.size() > 0) {
			HashMap<String, String> clientCredentials = decodeClientCredentials(auth);
			clientId = clientCredentials.get("clientId");
			clientSecret = clientCredentials.get("clientSecret");
		}
		
		
		//check for valid client
		if(request.getClientId() != null) {
			if(clientId != null) {
				//return 401 error "invalid_client"
				response.put("error", "duplicate_client_id");
				return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
			}
			clientId = request.getClientId();
			clientSecret = request.getClientSecret();
		}
		
		HashMap<String, String> client = this.searchClientsByClientId(clientId, this.clients);
		if(client == null) {
			//return 401 error "invalid_client"
			response.put("error", "invalid_client");
			return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
		}
		
		if(!client.get("clientSecret").equals(clientSecret)) {
			//return 401 error "invalid client"
			response.put("error", "invalid_client_secret");
			return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
		}
		
		//valid client. start processing token request for real
		if (request.getGrantType() != null) {
			if (request.getGrantType().equals("authorization_code")) {
				Optional<AuthorizationRequest> codeRequest = authRepo.findById(Long.parseLong(request.getCode()));
				
				AuthorizationRequest code = codeRequest.get();
				if (code != null) {
					authRepo.deleteById(code.getId());
					if (code.getClientId().equals(clientId)) {
						String access_token = this.generateRandomString(18);
						String refresh_token = this.generateRandomString(18);
						
						AccessToken token = new AccessToken();
						RefreshToken refreshToken = new RefreshToken();

						token.setAccessToken(access_token);
						token.setCreatedAt(new Date());
						token.setScope(code.getScope());
						tokenRepo.save(token);
						
						refreshToken.setRefreshToken(refresh_token);
						refreshToken.setClientId(clientId);
						refreshToken.setCreatedAt(new Date());
						refreshRepo.save(refreshToken);
						
						response.put("token", access_token);
						response.put("refreshToken", refreshToken.getId().toString());
						response.put("tokenId", token.getId().toString());
						response.put("token_type", "Bearer");
					} else {
						//return 400 error code "invalid_grant"
						response.put("error", "client_mismatch");
						return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
					}
				} else {
					//return 400 error "invalid_grant"
					response.put("error", "invalid_grant");
					return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
				}
			} else if(request.getGrantType().equals("client_credentials")) {
				String access_token = this.generateRandomString(18);
				String refresh_token = this.generateRandomString(18);
				
				AccessToken token = new AccessToken();
				RefreshToken refreshToken = new RefreshToken();
				
				token.setAccessToken(access_token);
				token.setCreatedAt(new Date());
				tokenRepo.save(token);
				
				refreshToken.setClientId(clientId);
				refreshToken.setCreatedAt(new Date());
				refreshToken.setRefreshToken(refresh_token);
				refreshRepo.save(refreshToken);
				
				response.put("token", access_token);
				response.put("tokenId", token.getId().toString());
				response.put("token_type", "Bearer");
				response.put("refresh_token", refreshToken.getId().toString());
			} else if(request.getGrantType().equals("refresh_token")) {
				String refreshTokenKey = request.getRefreshToken();
				RefreshToken refreshToken = refreshRepo.findById(refreshTokenKey);
				if(refreshToken != null) {
					if(refreshToken.getClientId().equals(clientId)) {
						String access_token = this.generateRandomString(18);
						AccessToken token = new AccessToken();
						token.setAccessToken(access_token);
						token.setCreatedAt(new Date());
						tokenRepo.save(token);
						response.put("token", access_token);
						response.put("tokenId", token.getId().toString());
						response.put("token_type", "Bearer");
						response.put("refresh_token", refreshToken.getId().toString());
					} else {
						refreshRepo.delete(refreshToken);
						response.put("error", "invalid_grant");
						return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
					}
				} else {
					response.put("error", "invalid_grant");
					return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
				}
			} else {
				//return 400 error "unsupported_grant_type"
				response.put("error", "unsupported_grant_type");
				return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
			}
		} else {
			//return 400 error "unsupported_grant_type"
			response.put("error", "unsupported_grant_type");
			return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
		}
		return new ResponseEntity<>(response, HttpStatus.ACCEPTED);
		
	}
	
}
