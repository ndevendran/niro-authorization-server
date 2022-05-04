package authserver.data;

import org.springframework.data.repository.CrudRepository;

import authserver.AuthorizationRequest;

public interface AuthorizationRequestRepository 
	extends CrudRepository<AuthorizationRequest, Long> {
	AuthorizationRequest findById(String id);
}
