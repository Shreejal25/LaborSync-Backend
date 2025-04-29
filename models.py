from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now

# Project Model

from django.db import models
from django.contrib.auth.models import User

# In models.py
from django.db import models
from django.utils import timezone
from datetime import date, timedelta

from django.db import models
from django.utils import timezone
from datetime import date, timedelta


from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone  

from django.db import models
from django.utils import timezone
#Reward Models

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()




class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    role = models.CharField(max_length=50, choices=[('manager', 'Manager'), ('worker', 'Worker'), ('', '---------')], default='worker', null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    gender = models.CharField(max_length=20, choices=[('male', 'Male'), ('female', 'Female'), ('others', 'Others'), ('', '---------')], null=True, blank=True)
    current_address = models.TextField(null=True, blank=True)
    permanent_address = models.TextField(null=True, blank=True)
    city_town = models.CharField(max_length=200, null=True, blank=True)
    state_province = models.CharField(max_length=200, null=True, blank=True)
    education_level = models.CharField(max_length=200, null=True, blank=True)
    certifications = models.TextField(blank=True, null=True)
    skills = models.TextField(null=True, blank=True)
    languages_spoken = models.TextField(null=True, blank=True)
    work_availability = models.CharField(max_length=20, choices=[('fulltime', 'Fulltime'), ('parttime', 'Part-time'), ('freelance', 'Freelance'), ('', '---------')], null=True, blank=True)
    work_schedule_preference = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.user.username
from django.db import models


class ManagerProfile(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='manager_profile', null=True, blank=True
    )
    company_name = models.CharField(max_length=255)
    work_location = models.CharField(max_length=255)

    def __str__(self):
        if self.user:  
            return f"{self.user.username} - Manager"
        return "Manager Profile (No User Assigned)"  
    
class Manager(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)  
    company_name = models.CharField(max_length=255)
    work_location = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.user.username} - {self.company_name}"


class Dashboard(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='dashboards') 
    description = models.TextField()
    clock_in_time = models.DateTimeField(null=True, blank=True)
    clock_out_time = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username}'s Dashboard"
    
    


class Project(models.Model):
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('on_hold', 'On Hold'),
    ]
    
  
      
    name = models.CharField(max_length=255)
    workers = models.ManyToManyField(User, related_name='projects')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    

    description = models.TextField(blank=True, null=True)
    budget = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    documents = models.FileField(upload_to='projects/documents/', blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True,related_name='created_projects')  # Fixed field
   
    start_date = models.DateField(default=date.today)
    
    def __str__(self):
        return self.name




class TimeLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    task = models.ForeignKey('Task', on_delete=models.SET_NULL, null=True, blank=True) #added task field.
    clock_in = models.DateTimeField(default=now)
    clock_out = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    

    def __str__(self):
        return f"TimeLog for {self.user.username}"
    



class Task(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
    ]
    
    min_clock_cycles = models.PositiveIntegerField(
        default=1,
        help_text="Number of clock-in/out cycles required per worker before task can be completed"
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.SET_NULL, related_name='tasks')
    task_title = models.CharField(max_length=255)
    description = models.TextField()
    estimated_completion_datetime = models.DateTimeField()
    assigned_shift = models.CharField(max_length=100)
    assigned_to = models.ManyToManyField(
        User,
        related_name='assigned_tasks',
        blank=True  # Makes the field optional
    )
    
    assigned_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_tasks', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status_changed_at = models.DateTimeField(auto_now_add=True)  # Tracks when status was last changed

    def __str__(self):
        return self.task_title

    def save(self, *args, **kwargs):
        # Check if status is being updated
        if self.pk:  # Only for updates, not creation
            original = Task.objects.get(pk=self.pk)
            if original.status != self.status:
                self.status_changed_at = timezone.now()
        super().save(*args, **kwargs)




class UserPoints(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='points')
    total_points = models.PositiveIntegerField(default=0)
    available_points = models.PositiveIntegerField(default=0)
    redeemed_points = models.PositiveIntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Points"



class Reward(models.Model):
    REWARD_TYPES = (
        ('bonus', 'Cash Bonus'),
        ('timeoff', 'Paid Time Off'),
        ('other', 'Other')
    )
    
    # Basic reward info
    name = models.CharField(max_length=100)
    description = models.TextField()
    point_cost = models.PositiveIntegerField()
    reward_type = models.CharField(max_length=20, choices=REWARD_TYPES)
    
    # Reward values
    cash_value = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    days_off = models.PositiveIntegerField(null=True, blank=True)
    
    # Status flags
    is_active = models.BooleanField(default=True)
    is_redeemable = models.BooleanField(default=True)
    redemption_instructions = models.TextField(blank=True)
    
    # Relationships
    task = models.ForeignKey(
        'Task', 
        on_delete=models.CASCADE, 
        related_name='rewards',
        null=True,
        blank=True
    )
    
    eligible_users = models.ManyToManyField(
        User,
        related_name='eligible_rewards',
        blank=True
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_rewards'
    )
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def can_be_redeemed_by(self, user):
        """Check if user can redeem this reward"""
        user_points = user.points
        has_access = not self.eligible_users.exists() or user in self.eligible_users.all()
        return (
            self.is_active 
            and self.is_redeemable
            and has_access
            and user_points.available_points >= self.point_cost
        )

    def __str__(self):
        return f"{self.name} ({self.point_cost} points)"
    


class PointsTransaction(models.Model):
    TRANSACTION_TYPES = (
        ('earn', 'Earned'),
        ('redeem', 'Redeemed'),
        ('adjust', 'Adjusted')
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='points_transactions')
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    points = models.IntegerField()
    description = models.CharField(max_length=255)
    related_task = models.ForeignKey(
        'Task', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='points_transactions'
    )
    related_reward = models.ForeignKey(
        'Reward',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='transactions'
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.get_transaction_type_display()} {self.points} points"