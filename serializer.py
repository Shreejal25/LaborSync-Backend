from rest_framework import generics,serializers,permissions
from .models import Dashboard, UserProfile,TimeLog,Manager, ManagerProfile, Project,UserPoints, PointsTransaction
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
from datetime import timedelta



class CombinedUserSerializer(serializers.ModelSerializer):
    user_profile = serializers.PrimaryKeyRelatedField(
        queryset=UserProfile.objects.all(), required=False
    )
    role = serializers.CharField(source='userprofile.role', required=False) 
    phone_number = serializers.CharField(source='userprofile.phone_number', required=False)
    gender = serializers.CharField(source='userprofile.gender', required=False)
    current_address = serializers.CharField(source='userprofile.current_address', required=False)
    permanent_address = serializers.CharField(source='userprofile.permanent_address', required=False)
    city_town = serializers.CharField(source='userprofile.city_town', required=False)
    state_province = serializers.CharField(source='userprofile.state_province', required=False)
    education_level = serializers.CharField(source='userprofile.education_level', required=False)
    certifications = serializers.CharField(source='userprofile.certifications', required=False)
    skills = serializers.CharField(source='userprofile.skills', required=False)
    languages_spoken = serializers.CharField(source='userprofile.languages_spoken', required=False)
    work_availability = serializers.CharField(source='userprofile.work_availability', required=False)
    work_schedule_preference = serializers.CharField(source='userprofile.work_schedule_preference', required=False)

    class Meta:
        model = User
        fields = [
            'username',
            'password',
            'email',
            'first_name',
            'last_name',
            'user_profile',
            'role',
            'phone_number',
            'gender',
            'current_address',
            'permanent_address',
            'city_town',
            'state_province',
            'education_level',
            'certifications',
            'skills',
            'languages_spoken',
            'work_availability',
            'work_schedule_preference'
        ]
        extra_kwargs = {'password': {'write_only': True}}
        
        
    def update(self, instance, validated_data):
    # Update User model fields
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.save()

        # Update UserProfile fields
        user_profile_data = validated_data.pop('userprofile', {})
        profile = instance.userprofile
        
        profile.profile_image = user_profile_data.get('profile_image', profile.profile_image)
        profile.role = user_profile_data.get('role', profile.role)
        profile.phone_number = user_profile_data.get('phone_number', profile.phone_number)
        profile.gender = user_profile_data.get('gender', profile.gender)
        profile.current_address = user_profile_data.get('current_address', profile.current_address)
        profile.permanent_address = user_profile_data.get('permanent_address', profile.permanent_address)
        profile.city_town = user_profile_data.get('city_town', profile.city_town)
        profile.state_province = user_profile_data.get('state_province', profile.state_province)
        profile.education_level = user_profile_data.get('education_level', profile.education_level)
        profile.certifications = user_profile_data.get('certifications', profile.certifications)
        profile.skills = user_profile_data.get('skills', profile.skills)
        profile.languages_spoken = user_profile_data.get('languages_spoken', profile.languages_spoken)
        profile.work_availability = user_profile_data.get('work_availability', profile.work_availability)
        profile.work_schedule_preference = user_profile_data.get('work_schedule_preference', profile.work_schedule_preference)
        
        profile.save()
        
        return instance
    def validate_phone_number(self, value):
        if value and len(value) > 15:
            raise serializers.ValidationError("Phone number is too long (max 15 characters).")
        return value

    def validate_gender(self, value):
        if value and len(value) > 10:
            raise serializers.ValidationError("Gender is too long (max 10 characters).")
        return value

    def validate_city_town(self, value):
        if value and len(value) > 100:
            raise serializers.ValidationError("City/Town is too long (max 100 characters).")
        return value

    def validate_state_province(self, value):
        if value and len(value) > 100:
            raise serializers.ValidationError("State/Province is too long (max 100 characters).")
        return value

    def validate_education_level(self, value):
        if value and len(value) > 100:
            raise serializers.ValidationError("Education level is too long (max 100 characters).")
        return value

    def validate_work_availability(self, value):
        if value and len(value) > 15:
            raise serializers.ValidationError("Work availability is too long (max 15 characters).")
        return value

    def validate_work_schedule_preference(self, value):
        if value and len(value) > 100:
            raise serializers.ValidationError("Work schedule preference is too long (max 100 characters).")
        return value
    def validate_role(self, value):
        if value and len(value) > 30:
            raise serializers.ValidationError('Role is too long (max 30 characters).')
        return value    

    def create(self, validated_data):
        user_profile_data = validated_data.pop('userprofile', {})
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        UserProfile.objects.create(
            user=user,
            
            profile_image=user_profile_data.get('profile_image', ''),
            phone_number=user_profile_data.get('phone_number', ''),
            gender=user_profile_data.get('gender', ''),
            current_address=user_profile_data.get('current_address', ''),
            permanent_address=user_profile_data.get('permanent_address', ''),
            city_town=user_profile_data.get('city_town', ''),
            state_province=user_profile_data.get('state_province', ''),
            education_level=user_profile_data.get('education_level', ''),
            certifications=user_profile_data.get('certifications', ''),
            skills=user_profile_data.get('skills', ''),
            languages_spoken=user_profile_data.get('languages_spoken', ''),
            work_availability=user_profile_data.get('work_availability', ''),
            work_schedule_preference=user_profile_data.get('work_schedule_preference', '')
        )
        return user
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        extra_kwargs = {
            'username': {'required': False},
            'email': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False}
        }

class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer()
  
    
    class Meta:
        model = UserProfile
        fields = '__all__' 
        
        
         
    
    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        
        # Update User model
        user_serializer = UserSerializer(instance.user, data=user_data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
        
        # Update UserProfile
        return super().update(instance, validated_data)
    
    
    
      
    
    
    
class ManagerProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(required=False)

    class Meta:
        model = ManagerProfile
        fields = ['user', 'company_name', 'work_location']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        user = instance.user
        
        # Updates user fields if they exist in user_data
        for field in ['email', 'first_name', 'last_name']:
            if field in user_data:
                setattr(user, field, user_data[field])
        
        # Only updates username if it's different and valid
        if 'username' in user_data and user_data['username'] != user.username:
            if not User.objects.filter(username=user_data['username']).exists():
                user.username = user_data['username']
        
        user.save()

        # Updates profile fields
        instance.company_name = validated_data.get('company_name', instance.company_name)
        instance.work_location = validated_data.get('work_location', instance.work_location)
        instance.save()

        return instance
            

# Manager Profile Serializer
class ManagerSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(required=True)
    work_location = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'first_name', 'last_name', 'company_name', 'work_location']
        extra_kwargs = {
            'password': {'write_only': True}  
        }

    def create(self, validated_data):
      
        company_name = validated_data.pop('company_name')
        work_location = validated_data.pop('work_location')

       
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])  #
        user.save()

      
        Manager.objects.create(user=user, company_name=company_name, work_location=work_location)

        return user  
    
    
# Project Serializer

class ProjectSerializer(serializers.ModelSerializer):
    workers = serializers.SlugRelatedField(
        queryset=User.objects.all(),
        slug_field='username',
        many=True,
        required=False
    )
    
    created_by = serializers.SlugRelatedField(
        read_only=True,
        slug_field='username'
    )
    
    class Meta:
        model = Project
        fields = '__all__'
        read_only_fields = ('created_by', 'created_at', 'updated_at')
        extra_kwargs = {
            'start_date': {'format': '%Y-%m-%d'},
            'end_date': {'format': '%Y-%m-%d'},
        }


class ProjectWorkerSerializer(serializers.Serializer):
    project_name = serializers.CharField(source='name')  # Access project name
    workers = serializers.SerializerMethodField()

    class Meta:
         model = Project
         fields = ['workers']
         
    def get_workers(self, obj):
        workers = obj.workers.all()
        return UserSerializer(workers, many=True).data
         
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']

class DashboardSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dashboard
        fields = ['id', 'description']
        


from rest_framework import serializers
from .models import TimeLog, Task

class ClockTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'task_title', 'assigned_shift']

class ClockInClockOutSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    clock_in = serializers.DateTimeField(format='iso-8601', read_only=True)  
    clock_out = serializers.DateTimeField(format='iso-8601', read_only=True)
    task = ClockTaskSerializer(read_only=True)  # Include full task details
    note = serializers.CharField(read_only=True, allow_null=True)  # Include note field

    class Meta:
        model = TimeLog
        fields = ['username', 'clock_in', 'clock_out', 'task', 'note']

    def update(self, instance, validated_data):
        if 'clock_in' in validated_data:
            instance.clock_in = validated_data['clock_in']
        if 'clock_out' in validated_data:
            instance.clock_out = validated_data['clock_out']
        instance.save()
        return instance
    


from rest_framework import serializers
from .models import Task

class TaskSerializer(serializers.ModelSerializer):
    assigned_by = serializers.ReadOnlyField(source="assigned_by.username")
    assigned_to = serializers.SlugRelatedField(
        queryset=User.objects.all(),
        slug_field='username',
        many=True,
        required=True
    )
    project = serializers.PrimaryKeyRelatedField(
        queryset=Project.objects.all(),
        required=True
    )
    status = serializers.ChoiceField(
        choices=Task.STATUS_CHOICES,
        default='pending',
        required=False
    )
    estimated_completion_datetime = serializers.DateTimeField(
        default=lambda: timezone.now() + timedelta(days=1)  # Default to 1 day from now
    )

    class Meta:
        model = Task
        fields = [
            'id',
            'project',
            'task_title',
            'description',
            'estimated_completion_datetime',
            'assigned_shift',
            'assigned_to',
            'assigned_by',
            'status',
            'created_at',
            'updated_at',
            'status_changed_at',
            'min_clock_cycles',
        ]
        extra_kwargs = {
            'task_title': {'required': True},
            'description': {'required': True},
            'estimated_completion_datetime': {
                'required': True,
                'allow_null': False
            },
            'assigned_shift': {'required': True},
            'min_clock_cycles': {'required': False, 'default': 1},
        }

    def create(self, validated_data):
        try:
            print("Validated data in create:", validated_data)  # Add this line
            request = self.context.get('request')
            assigned_to = validated_data.pop('assigned_to')

            # Creates the task instance
            task = Task.objects.create(
                **validated_data,
                assigned_by=request.user,
                status_changed_at=timezone.now()
            )

            # Sets many-to-many relationship
            task.assigned_to.set(assigned_to)

            return task

        except Exception as e:
            raise serializers.ValidationError({
                'non_field_errors': [f"Failed to create task: {str(e)}"]
            })

    def update(self, instance, validated_data):
        assigned_to = validated_data.pop('assigned_to', None)
        
        if 'status' in validated_data and instance.status != validated_data['status']:
            validated_data['status_changed_at'] = timezone.now()
        
        # Updating regular fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        
        # Updating many-to-many relationship if provided
        if assigned_to is not None:
            instance.assigned_to.set(assigned_to)
        
        return instance
    
    
class TaskViewSerializer(serializers.ModelSerializer):
    assigned_by = serializers.CharField(source="assigned_by.username", read_only=True)
    assigned_to = serializers.SerializerMethodField()
    project_name = serializers.CharField(source="project.name", read_only=True)
    
    class Meta:
        model = Task
        fields = [
            'id',
            'project',
            'project_name',
            'task_title',
            'description',
            'estimated_completion_datetime',
            'assigned_shift',
            'assigned_to',
            'assigned_by',
            'status',
            'created_at',
            'updated_at',
            'status_changed_at'
            
        ]
    
    def get_assigned_to(self, obj):
        # Returns array of assigned usernames
        return [user.username for user in obj.assigned_to.all()]
    




class SimpleTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'task_title', 'status', 'project', 'assigned_shift']

class PointsTransactionSerializer(serializers.ModelSerializer):
    reward_name = serializers.SerializerMethodField()
    task_title = serializers.SerializerMethodField()
    reward_details = serializers.SerializerMethodField()
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = PointsTransaction
        fields = [
            'id', 
            'username',
            'transaction_type',
            'points',
            'description',
            'timestamp',
            'related_task',
            'related_reward',
            'task_title',
            'reward_name',
            'reward_details', 
        ]
        read_only_fields = ['timestamp']

    def get_task_title(self, obj):
            if obj.related_task:
                return obj.related_task.task_title 
            return None


    def get_reward_name(self, obj):
        if obj.related_reward:
            return obj.related_reward.name
        return None

    def get_reward_details(self, obj):
        if obj.related_reward:
            return {
                'id': obj.related_reward.id,
                'name': obj.related_reward.name,
                'type': obj.related_reward.reward_type
            }
        return None



from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Reward, UserPoints

class RewardSerializer(serializers.ModelSerializer):
    is_affordable = serializers.SerializerMethodField()
    task_details = serializers.SerializerMethodField()
    task_title = serializers.SerializerMethodField()
    eligible_users = serializers.SlugRelatedField(
        many=True,
        slug_field='username',
        queryset=User.objects.all(),
        required=False
    )

    class Meta:
        model = Reward
        fields = [
            'id',
            'name',
            'description',
            'point_cost',
            'reward_type',
            'cash_value',
            'days_off',
            'is_active',
            'is_affordable',
            'task_title',
            'task_details',
            'eligible_users'  # Added eligible_users
        ]

    def get_is_affordable(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            user_points = UserPoints.objects.get_or_create(user=request.user)[0]
            return user_points.available_points >= obj.point_cost
        return False

    def get_task_title(self, obj):
        if obj.task:
            return obj.task.task_title
        return None

    def get_task_details(self, obj):
        if obj.task:
            return {
                'id': obj.task.id,
                'title': obj.task.task_title,
                'description': obj.task.description
            }
        return None

    def update(self, instance, validated_data):
        # Handle eligible_users separately to update ManyToManyField
        eligible_users = validated_data.pop('eligible_users', None)
        instance = super().update(instance, validated_data)
        
        if eligible_users is not None:
            instance.eligible_users.set(eligible_users)
        
        return instance

class UserPointsSerializer(serializers.ModelSerializer):
    transactions = PointsTransactionSerializer(many=True, read_only=True, source='points_transactions')
    
    

    class Meta:
        model = UserPoints
        fields = [
            'total_points',
            'available_points',
            'redeemed_points',
            'last_updated',
            'transactions',
            
        ]

   

    
    

class RewardCreateSerializer(serializers.ModelSerializer):
    
    
    eligible_users = serializers.SlugRelatedField(
        many=True,
        slug_field='username',  # Match based on username
        queryset=User.objects.all(),
        required=False
    )
    
    task = serializers.PrimaryKeyRelatedField(
        queryset=Task.objects.all(),
        required=False,
        allow_null=True
    )
        
    class Meta:
        model = Reward
        fields = [
            'name',
            'description',
            'point_cost',
            'reward_type',
            'cash_value',
            'days_off',
            'is_active',
            'is_redeemable',
            'redemption_instructions',
            'task',  
            'eligible_users'  
        ]
        extra_kwargs = {
            'eligible_users': {'required': False}, #
            'task': {'required': False}
        }