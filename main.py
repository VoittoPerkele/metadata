import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import exifread
import piexif

import cProfile
import pstats


# Функции обработки GPS

def convert_gps_to_decimal(gps_data):
    try:
        d = gps_data[0][0] / gps_data[0][1]  # градусы
        m = gps_data[1][0] / gps_data[1][1]  # минуты
        s = gps_data[2][0] / gps_data[2][1]  # секунды

        return d + (m / 60) + (s / 3600)
    except Exception:
        return None


def extract_gps_from_piexif(path):
    try:
        exif_dict = piexif.load(path)
        gps_info = exif_dict.get("GPS")
        if not gps_info:
            return {}
        gps_data = {}

        # Перебор GPS тегов
        for tag, value in gps_info.items():
            tag_name = GPSTAGS.get(tag, tag)
            gps_data[tag_name] = value

        # Конвертация широты
        if "GPSLatitude" in gps_data and "GPSLatitudeRef" in gps_data:
            lat = convert_gps_to_decimal(gps_data["GPSLatitude"])
            if gps_data["GPSLatitudeRef"].decode() == "S":
                lat = -lat
            gps_data["LatitudeDecimal"] = lat

        # Конвертация долготы
        if "GPSLongitude" in gps_data and "GPSLongitudeRef" in gps_data:
            lon = convert_gps_to_decimal(gps_data["GPSLongitude"])
            if gps_data["GPSLongitudeRef"].decode() == "W":
                lon = -lon
            gps_data["LongitudeDecimal"] = lon

        return gps_data
    except Exception:
        return {}


# Извлечение EXIF данных

def extract_pillow_exif(path):
    try:
        with Image.open(path) as img:
            exif = img._getexif()  # получение EXIF словаря
            if not exif:
                return {}
            return {TAGS.get(k, k): v for k, v in exif.items()}
    except Exception:
        return {}


def extract_exifread(path):
    try:
        with open(path, 'rb') as f:
            tags = exifread.process_file(f)  # чтение через exifread
            return {k: str(v) for k, v in tags.items()}
    except Exception:
        return {}


def extract_piexif(path):
    try:
        exif_dict = piexif.load(path)
        meta = {}
        for ifd in exif_dict:
            if isinstance(exif_dict[ifd], dict):
                for tag, value in exif_dict[ifd].items():
                    meta[f"{ifd}:{tag}"] = str(value)
        return meta
    except Exception:
        return {}


# GUI

def choose_file():
    path = filedialog.askopenfilename(
        title="Выберите изображение",
        filetypes=[("Images", "*.jpg *.jpeg *.png *.tiff *.webp *.heic *.arw *.dng")]
    )
    if path:
        file_path_var.set(path)
        extract_metadata()

# Извлечение всех типов метаданных
def extract_metadata():
    path = file_path_var.get().strip()
    if not path or not os.path.exists(path):
        messagebox.showerror("Ошибка", "Файл не найден")
        return
    output.delete(1.0, tk.END)
    output.insert(tk.END, f"Файл: {path}\n")
    output.insert(tk.END, "-" * 70 + "\n\n")

    pillow_exif = extract_pillow_exif(path)
    exifread_exif = extract_exifread(path)
    piexif_exif = extract_piexif(path)
    gps_data = {}
    if pillow_exif:
        gps_data = extract_gps_from_piexif(path)

    def print_dict(title, data):
        output.insert(tk.END, f"===== {title} =====\n")
        if not data:
            output.insert(tk.END, "Нет данных\n\n")
            return
        for k, v in data.items():
            output.insert(tk.END, f"{k}: {v}\n")
        output.insert(tk.END, "\n")

    print_dict("EXIF (Pillow)", pillow_exif)
    print_dict("EXIF (ExifRead — расширенный)", exifread_exif)
    print_dict("EXIF (piexif — низкоуровневый)", piexif_exif)
    print_dict("GPS координаты", gps_data)

    output.insert(tk.END, "-" * 70 + "\n")
    output.insert(tk.END, "Готово\n")


# Создание окна приложения

root = tk.Tk()  # создание основного окна
root.title("Извлечение метаданных из фотографий")
root.geometry("800x600")

file_path_var = tk.StringVar()

# Верхняя панель с кнопками
top_frame = tk.Frame(root)
top_frame.pack(pady=10)

tk.Label(top_frame, text="Путь к файлу:").pack(side=tk.LEFT, padx=5)
tk.Entry(top_frame, textvariable=file_path_var, width=70).pack(side=tk.LEFT, padx=5)
tk.Button(top_frame, text="Выбрать", command=choose_file).pack(side=tk.LEFT, padx=5)
tk.Button(top_frame, text="Извлечь", command=extract_metadata).pack(side=tk.LEFT, padx=5)

# Окно вывода текста
output = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

root.mainloop()  # запуск GUIif __name__ == "__main__":
    profiler = cProfile.Profile()
    profiler.enable()

    root.mainloop()  # запуск GUI

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative").print_stats(20)



