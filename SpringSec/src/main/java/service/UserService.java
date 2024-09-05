package service;

import model.entity.User;
import model.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private UserRepository userRepository;
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElse(null);
    }


}
