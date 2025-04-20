import psutil
import shutil

async def get_system_info_service():
    cpu_usage = psutil.cpu_percent(interval=1)
    total, used, free = shutil.disk_usage("/")
    cloud_usage_percentage = (used / total) * 100
    memory = psutil.virtual_memory()

    return {
        'cpu_usage': cpu_usage,
        'cloud_usage_total': f"{total / (1024.0 ** 3):.2f} GB",
        'cloud_usage_used': f"{used / (1024.0 ** 3):.2f} GB",
        'cloud_usage_percentage': cloud_usage_percentage,
        'memory_usage_total': f"{memory.total / (1024.0 ** 3):.2f} GB",
        'memory_usage_used': f"{memory.used / (1024.0 ** 3):.2f} GB",
        'memory_usage_percentage': memory.percent,
    }
