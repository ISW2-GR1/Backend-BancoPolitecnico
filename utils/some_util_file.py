def validate_ecuadorian_cedula(cedula):
    # Verificar que la cédula tenga exactamente 10 dígitos y sea numérica
    if len(cedula) != 10 or not cedula.isdigit():
        return False

    # Obtener el dígito verificador
    d_ver = int(cedula[-1])
    total = 0

    # Calcular la suma total usando el algoritmo de validación
    for i in range(9):
        mult = 2 if i % 2 == 0 else 1
        res = int(cedula[i]) * mult
        
        # Ajustar si el resultado es mayor o igual a 10
        if res >= 10:
            res -= 9
        
        total += res

    # Calcular el dígito verificador esperado
    total = total % 10
    if total != 0:
        total = 10 - total
    
    return total == d_ver
