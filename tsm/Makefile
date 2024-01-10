
setup:
	docker compose up --quiet-pull -d 

teardown:
	docker compose down

tsm-up:
	docker compose up -d tsm_node_0 tsm_node_1 tsm_node_2

tsm-down:
	docker compose stop tsm_node_0 tsm_node_1 tsm_node_2

logs:
	docker compose logs
