package com.kernel360.orury.domain.user.db;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
	Optional<RefreshTokenEntity> findByUserIdAndReissueCountLessThan(Long id, int count);
}
