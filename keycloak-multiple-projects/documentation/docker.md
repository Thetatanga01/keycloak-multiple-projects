

export COMPOSE_BAKE=true
docker-compose down
docker-compose build --no-cache
COMPOSE_BAKE=true docker-compose up -d