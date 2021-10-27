from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator


# Create your models here.
class Trip(models.Model):
    longitude_rx = models.DecimalField(max_digits=8, decimal_places=5, validators=[
            MaxValueValidator(180),
            MinValueValidator(-180)
        ])
    longitude_tx = models.DecimalField(max_digits=8, decimal_places=5, validators=[
            MaxValueValidator(180),
            MinValueValidator(-180)
        ])

    latitude_rx = models.DecimalField(max_digits=7, decimal_places=5, validators=[
            MaxValueValidator(90),
            MinValueValidator(-90)
        ])
    latitude_tx = models.DecimalField(max_digits=7, decimal_places=5, validators=[
            MaxValueValidator(90),
            MinValueValidator(-90)
        ])

    distance = models.DecimalField(max_digits=8, decimal_places=5, validators=[
            MaxValueValidator(180),
            MinValueValidator(-180)
        ])

    connected = models.BooleanField(default=True)

    time = models.DateTimeField()

    def __str__(self):
        return f'{self.id} {self.time}'
