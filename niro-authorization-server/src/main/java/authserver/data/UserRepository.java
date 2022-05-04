package authserver.data;

import org.springframework.data.repository.CrudRepository;

import authserver.User;

public interface UserRepository extends CrudRepository<User, Long> {
	User findByUsername(String username);
}
