# Gestión de Túneles SSM con AWS
Este script permite gestionar túneles SSM (AWS Systems Manager) para realizar port forwarding hacia hosts remotos en AWS. Utiliza `boto3` para interactuar con AWS y maneja sesiones en segundo plano.

## Requisitos
- Python 3.8 o superior
- AWS CLI configurado con un perfil v
álido (`aws configure`)
- Permisos para ejecutar comandos SSM en la instancia EC2

## Instalación
```bash
pip install -r requirements.txt
```

## Uso

### Iniciar túnel
```
python main.py start --name test-rds-session --instance-id i-1234567890abcdef --remote-host database.example.com --remote-port 5432 --local-port 5432 --aws-profile mi_perfil --region us-west-1
```

### Detener túnel
```
python main.py stop test-rds-session --aws-profile mi_perfil --region us-west-1
```
## Notas
- Los archivos PID se guardan en la carpeta `pids/`.
- Los archivos con el Session ID se guardan en la carpeta `sessions/`.
- Asegúrate de tener permisos de IAM adecuados para utilizar AWS SSM y describir/terminar sesiones.




