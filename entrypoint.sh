#!/bin/bash

# Ejecutar migraciones
python manage.py migrate --no-input

# Iniciar el servidor
exec "$@"
