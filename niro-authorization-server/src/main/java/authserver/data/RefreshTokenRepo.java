package authserver.data;

import org.springframework.data.repository.CrudRepository;

import authserver.RefreshToken;

public interface RefreshTokenRepo extends CrudRepository<RefreshToken, Long> {
	RefreshToken findById(String id);
}
