package authserver.data;

import org.springframework.data.repository.CrudRepository;

import authserver.AccessToken;

public interface AccessTokenRepo extends CrudRepository<AccessToken, Long> {
	AccessToken findById(String id);
}
