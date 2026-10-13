.PHONY: all clean fclean re test web
all:
	chmod +x mypgp
clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
fclean: clean
re: fclean all
test:
	python3 -m unittest discover -s tests -v
web:
	python3 -m my_pgp.web
