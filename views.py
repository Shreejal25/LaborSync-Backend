from django.shortcuts import render, get_object_or_404
from django.http import QueryDict
from django.contrib.auth.models import User

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.paginator import Paginator, EmptyPage
from django.core.mail import send_mail

from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from rest_framework.authtoken.models import Token  
from rest_framework import viewsets, status
from django.utils.http import urlsafe_base64_encode
from django.db.models import Count, Q
from django.db import transaction
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.conf import settings
from .permission import IsManager

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import Group
from .models import Task




from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import ManagerProfile 



from .models import Dashboard, UserProfile,TimeLog,ManagerProfile, Task, Project, UserPoints, PointsTransaction, Reward
from rest_framework import generics, permissions, status
from django.contrib.auth import authenticate
from django.contrib.auth.models import Group
from .serializer import( DashboardSerializer, CombinedUserSerializer,
ClockInClockOutSerializer, UserProfileSerializer,UserSerializer,
ManagerSerializer,ManagerProfileSerializer,TaskSerializer, 
TaskViewSerializer, ProjectSerializer, ProjectWorkerSerializer,
UserPointsSerializer, RewardSerializer, RewardCreateSerializer,
PointsTransactionSerializer)
from rest_framework.decorators import api_view, permission_classes
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.utils import timezone
from datetime import datetime

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            tokens = response.data

            access_token = tokens['access']
            refresh_token = tokens['refresh']

            res = Response()

            res.data = {'success': True}

            res.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=True,
                samesite='None',
                path='/'
            )
            res.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite='None',
                path='/'
            )
            is_manager = False
            user = authenticate(username=request.data.get('username'), password=request.data.get('password'))

            if user is not None:
                is_manager = user.groups.filter(name='Managers').exists()

            res.data['is_manager'] = is_manager
            res.data['dashboard_type'] = 'manager' if is_manager else 'user' #adding dashboard type

            return res
        except:
            return Response({'success': False, 'dashboard_type' : 'user'}) #add dashboard type even if failed.


class CustomRefreshTokenView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.COOKIES.get('refresh_token')  # Read from cookie
            if not refresh_token:
                return Response({'error': 'No refresh token found'}, status=status.HTTP_401_UNAUTHORIZED)

            request.data['refresh'] = refresh_token
            response = super().post(request, *args, **kwargs)

            if 'access' not in response.data:
                return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

            access_token = response.data['access']

            res = Response({'refreshed': True})
            res.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=False,  # Set True in production
                samesite='None',
                path='/'
            )
            return res
        except:
            return Response({'error': 'Refresh failed'}, status=status.HTTP_401_UNAUTHORIZED)



@api_view(['POST'])
def logout(request):
    try:
        res = Response()
        res.data = {'success': True}
        res.delete_cookie('access_token', path='/', samesite='None')
        res.delete_cookie('refresh_token', path='/', samesite='None')
        return res
    except:
        return Response({'success': False})

@api_view(['POST'])
@permission_classes([IsAuthenticated])  
def is_authenticated(request):
    return Response({'authenticated': True})
    


@api_view(['POST'])
@permission_classes([AllowAny])
def register_manager(request):
    serializer = ManagerSerializer(data=request.data)

    if serializer.is_valid():
        manager_user = serializer.save() 

        
        company_name = request.data.get('company_name', '')
        work_location = request.data.get('work_location', '')

      
        ManagerProfile.objects.create(
            user=manager_user,
            company_name=company_name,
            work_location=work_location
        )

       
        manager_group, created = Group.objects.get_or_create(name='Managers')
        manager_group.user_set.add(manager_user)  

        return Response({'message': 'Manager registered successfully!'}, status=201)

    return Response(serializer.errors, status=400)




@api_view(['POST'])
@permission_classes([AllowAny])
def login_manager(request):
    username = request.data.get('username')
    password = request.data.get('password')
    
    user = authenticate(username=username, password=password)
    
   
    
    if user is not None:
      
        is_manager = user.groups.filter(name='Managers').exists()
        return Response({
            'message': 'Login successful',
            'is_manager': is_manager
        }, status=200)
    
    return Response({'error': 'Invalid credentials'}, status=400)


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = CombinedUserSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = serializer.save()

        # Automatically adds the user to the "Workers" group
        workers_group, created = Group.objects.get_or_create(name="Workers")
        user.groups.add(workers_group)

        return Response({'message': 'User registered successfully and added to Workers group!'}, status=201)
    
    return Response(serializer.errors, status=400)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def manager_dashboard_view(request):
    user = request.user

    # Check if the user is a manager
    if not user.groups.filter(name='Managers').exists():
        return Response({'error': 'Access denied. User is not a manager.'}, status=status.HTTP_403_FORBIDDEN)

    try:
        manager_profile = ManagerProfile.objects.get(user=user)
    except ManagerProfile.DoesNotExist:
        return Response({'error': 'Manager profile not found.'}, status=status.HTTP_404_NOT_FOUND)

    # Fetch manager-specific data
    tasks = Task.objects.filter(assigned_by=user)
    total_tasks_assigned = tasks.count()
    active_tasks = tasks.filter(status='in_progress').count()
    completed_tasks = tasks.filter(status='completed').count()
    recent_tasks = tasks.order_by('-created_at')[:7]

    # Serialize data
    manager_serializer = ManagerProfileSerializer(manager_profile)
    task_serializer = TaskViewSerializer(recent_tasks, many=True)

    return Response({
        'dashboard_type': 'manager',
        'manager_profile': manager_serializer.data,
        'stats': {
            'total_tasks_assigned': total_tasks_assigned,
            'active_tasks': active_tasks,
            'completed_tasks': completed_tasks,
        },
        'recent_tasks': task_serializer.data
    })
    
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_dashboard_view(request):
    user = request.user

    if user.groups.filter(name='Managers').exists():
        return Response({'error': 'Access denied. User is a manager.'}, status=status.HTTP_403_FORBIDDEN)

    dashboards = Dashboard.objects.filter(user=user)
    serializer = DashboardSerializer(dashboards, many=True)

    return Response({
        'dashboard_type': 'user',
        'dashboards': serializer.data
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_role_view(request):
    user = request.user
    is_manager = user.groups.filter(name='Managers').exists()
    return Response({
        'role': 'manager' if is_manager else 'user'
    })









@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_worker(request):
    # Check if user is a manager
    if not request.user.groups.filter(name='Managers').exists():
        return Response(
            {'success': False, 'message': 'Only managers can invite workers.'},
            status=403
        )

    # Get manager's profile
    try:
        manager_profile = ManagerProfile.objects.get(user=request.user)
    except ManagerProfile.DoesNotExist:
        return Response(
            {'success': False, 'message': 'Manager profile not found.'},
            status=404
        )

    # Get worker's email from request
    worker_email = request.data.get('email')
    if not worker_email:
        return Response(
            {'success': False, 'message': 'Email is required.'},
            status=400
        )

    # Prepare email content
    company_name = manager_profile.company_name
    manager_name = request.user.username  # Or use first_name + last_name if available
    registration_link = "http://localhost:3000/register/"

    subject = f'Invitation to Join {company_name}'
    message = (
        f"You have been invited by\n\n"
        f"Company Name: {company_name}\n"
        f"Manager Name: {manager_name}\n\n"
        f"Click the link below to register as a worker:\n{registration_link}"
    )

    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [worker_email],
            fail_silently=False,
        )
        return Response({
            'success': True,
            'message': 'Invitation email sent successfully.'
        })
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Failed to send invitation email: {str(e)}'
        }, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_workers(request):
    user = request.user

    # Ensure only managers can access this endpoint
    if not user.groups.filter(name='Managers').exists():
        return Response({'error': 'Access denied. Only managers can view workers.'}, status=status.HTTP_403_FORBIDDEN)

    workers = UserProfile.objects.exclude(user__groups__name='Managers')  # Exclude managers
    serializer = UserProfileSerializer(workers, many=True)
    
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_clock_history(request):
    user = request.user

    # If the user is a manager, fetch clock history for all workers
    if user.groups.filter(name='Managers').exists():
        clock_history = TimeLog.objects.all().order_by('clock_in')
    else:
        # If the user is not a manager, return only their clock history
        clock_history = TimeLog.objects.filter(user=user).order_by('clock_in')

    serializer = ClockInClockOutSerializer(clock_history, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def create_user_profile(request):
   
    user = request.user
    # Check if a profile already exists.
    if UserProfile.objects.filter(user=user).exists():
        return Response({"detail": "User profile already exists."}, status=status.HTTP_400_BAD_REQUEST)

    serializer = UserProfileSerializer(data=request.data)

    if serializer.is_valid():
        serializer.save(user=user)  # Associate the profile with the user
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile_detail_view(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        return Response({"detail": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = UserProfileSerializer(
            user_profile,
            context={'request': request}
        )
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = UserProfileSerializer(
            user_profile,
            data=request.data,
            partial=True,
            context={'request': request}
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def manager_profile_view(request):
    try:
        manager_profile = ManagerProfile.objects.get(user=request.user)
    except ManagerProfile.DoesNotExist:
        return Response({'error': 'Manager profile not found.'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        return handle_get_manager_profile(manager_profile)

    elif request.method == 'PUT':
        return handle_put_manager_profile(request, manager_profile)


def handle_get_manager_profile(manager_profile):
    serializer = ManagerProfileSerializer(manager_profile)
    return Response(serializer.data)


def handle_put_manager_profile(request, manager_profile):
    data = request.data.copy()
    current_user = request.user

    user_data = extract_user_data(data, current_user)

    if user_data:
        data['user'] = user_data

    serializer = ManagerProfileSerializer(
        manager_profile,
        data=data,
        partial=True,
        context={'request': request}
    )

    try:
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data)
    except serializers.ValidationError as e:
        return handle_validation_error(e, user_data, current_user, manager_profile, data, request)


def extract_user_data(data, current_user):
    user_fields = ['username', 'email', 'first_name', 'last_name']
    user_data = {}

    if 'user' in data:
        user_data.update(data.pop('user', {}))

    for field in user_fields:
        if field in data:
            user_data[field] = data.pop(field)

    if 'username' in user_data and user_data['username'] == current_user.username:
        user_data.pop('username')

    return user_data


def handle_validation_error(e, user_data, current_user, manager_profile, data, request):
    if is_username_error(e):
        user_data = handle_username_error(user_data, current_user)
        return save_manager_profile(manager_profile, data, request, user_data)

    return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)


def is_username_error(e):
    return 'user' in e.detail and 'username' in e.detail['user'] and any(
        "already exists" in msg for msg in e.detail['user']['username']
    )


def handle_username_error(user_data, current_user):
    if 'username' in user_data and user_data['username'] == current_user.username:
        user_data.pop('username')
    return user_data


def save_manager_profile(manager_profile, data, request, user_data):
    serializer = ManagerProfileSerializer(
        manager_profile,
        data=data,
        partial=True,
        context={'request': request}
    )
    if serializer.is_valid(raise_exception=True):
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def clock_in(request):
    """Handle clock-in operation"""
    task_id = request.data.get('task_id')
    if not task_id:
        return Response({"error": "task_id is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        task = Task.objects.get(id=task_id, assigned_to=request.user)
        
        # Check if user already has an active clock-in
        active_clock = TimeLog.objects.filter(
            user=request.user,
            clock_out__isnull=True
        ).first()
        
        if active_clock:
            return Response({
                "message": "You already have an active clock-in",
                "clock_in": active_clock.clock_in,
                "task_id": active_clock.task.id
            }, status=status.HTTP_200_OK)
            
        # Create new clock-in
        clock_in = TimeLog.objects.create(
            user=request.user,
            task=task,
            clock_in=timezone.now()
        )
        
        return Response({
            "message": "Clocked in successfully",
            "clock_in": clock_in.clock_in,
            "task_id": task.id
        }, status=status.HTTP_201_CREATED)
        
    except Task.DoesNotExist:
        return Response({"error": "Task not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_active_clock(request):
    """Check if user has an active clock-in"""
    active_clock = TimeLog.objects.filter(
        user=request.user,
        clock_out__isnull=True
    ).first()
    
    if active_clock:
        return Response({
            "is_active": True,
            "clock_in": active_clock.clock_in,
            "task_id": active_clock.task.id,
            "task_title": active_clock.task.task_title
        }, status=status.HTTP_200_OK)
    
    return Response({
        "is_active": False
    }, status=status.HTTP_200_OK)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from .models import Task, TimeLog
from rest_framework import status

def check_task_completion(task):
    """Check if all workers have completed required clock cycles"""
    for user in task.assigned_to.all():
        completed_cycles = TimeLog.objects.filter(
            user=user,
            task=task,
            clock_out__isnull=False
        ).count()
        
        if completed_cycles < task.min_clock_cycles:
            return False
    return True

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def clock_out(request):
    """Handle basic clock-out operation without auto-completion or rewards"""
    try:
        user = request.user
        task_id = request.data.get('task_id')
        
        if not task_id:
            return Response({"error": "task_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Verify task exists and is assigned to user
        task = Task.objects.get(id=task_id, assigned_to=user)
        
        # Find the latest active clock-in
        latest_log = TimeLog.objects.filter(
            user=user,
            task=task,
            clock_out__isnull=True
        ).latest('clock_in')

        # Record clock-out time
        latest_log.clock_out = timezone.now()
        latest_log.save()

        # Simple response without completion checks or rewards
        return Response({
            "message": "Clocked out successfully",
            "clock_in": latest_log.clock_in,
            "clock_out": latest_log.clock_out,
            "duration": (latest_log.clock_out - latest_log.clock_in).total_seconds() / 3600  # hours
        }, status=status.HTTP_200_OK)

    except TimeLog.DoesNotExist:
        return Response({"error": "No active clock-in found"}, status=status.HTTP_400_BAD_REQUEST)
    except Task.DoesNotExist:
        return Response({"error": "Task not found or not assigned to user"}, status=status.HTTP_404_NOT_FOUND)



@api_view(['POST'])
@permission_classes([IsAuthenticated, IsManager])
def complete_task(request, task_id):
    try:
        # Get task first
        task = Task.objects.get(id=task_id)

        # Permission check
        if (task.assigned_to != request.user and 
            getattr(task, 'assigned_by', None) != request.user and 
            not request.user.is_manager):
            return Response(
                {"message": "You don't have permission to complete this task"},
                status=403
            )

        if task.status == 'completed':
            return Response({"message": "Task is already completed"}, status=400)

        # ❗ Skip requirement check and force complete
        task.status = 'completed'
        task.completed_by = request.user
        task.completed_at = timezone.now()
        task.save()

        return Response({
            "message": "Task successfully completed",
            "task": TaskSerializer(task).data
        }, status=200)

    except Task.DoesNotExist:
        return Response({"message": "Task not found"}, status=404)

    

def get_completion_progress(task):
    """Get completion progress for all workers"""
    progress = []
    for user in task.assigned_to.all():
        completed = TimeLog.objects.filter(
            user=user,
            task=task,
            clock_out__isnull=False
        ).count()
        progress.append({
            "user": user.username,
            "completed_cycles": completed,
            "required_cycles": task.min_clock_cycles,
            "complete": completed >= task.min_clock_cycles
        })
    return progress

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_project(request):
    data = request.data.copy()
    serializer = ProjectSerializer(data=data, context={'request': request})
    
    if serializer.is_valid():
       
        project = serializer.save(created_by=request.user)
        return Response(ProjectSerializer(project).data, status=201)
    return Response(serializer.errors, status=400)



from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from rest_framework.decorators import parser_classes


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser, JSONParser])
def update_project(request, project_id):
    # Get project and verify ownership
    project = get_object_or_404(Project, pk=project_id)
    if project.created_by != request.user:
        return Response({'error': 'Not authorized to update this project'}, status=403)

    # Prepare data and serializer
    data = request.data.copy()
    serializer = ProjectSerializer(
        project,
        data=data,
        partial=True,
        context={'request': request}  # Match create_project's context
    )

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)

    # Return detailed errors for debugging
    return Response(serializer.errors, status=400)








@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_projects(request):
    try:
        # Get projects where user is creator OR assigned worker
        projects = Project.objects.filter(
            Q(created_by=request.user) | 
            Q(workers__username=request.user.username)
        ).distinct()
        
        if not projects.exists():
            return Response(
                {"detail": "No projects found."},
                status=status.HTTP_200_OK
            )
            
        serializer = ProjectSerializer(projects, many=True)
        return Response({
            "count": projects.count(),
            "projects": serializer.data
        })
        
    except Exception as e:
        return Response(
            {"error": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_project(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    
    # Verifys the requesting user is the project creator
    if project.created_by != request.user:
        return Response({'error': 'Not authorized to delete this project'}, status=403)
    
    project.delete()
    return Response({'message': 'Project deleted successfully'}, status=204)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def assign_task(request):

    user = request.user

    if not user.groups.filter(name='Managers').exists():
        return Response({'error': 'You do not have permission to assign tasks.'}, status=403)

    serializer = TaskSerializer(data=request.data, context={'request': request})

    if serializer.is_valid():
        serializer.save()
        return Response({'message': 'Task assigned successfully!'}, status=201)

    return Response(serializer.errors, status=400)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_task(request, task_id):
    user = request.user
    
    if not user.groups.filter(name='Managers').exists():
        return Response({'error': 'Permission denied'}, status=403)
    
    task = get_object_or_404(Task, pk=task_id)
    
    # Log for debugging
    print("Incoming data:", request.data)
    
    serializer = TaskSerializer(
        task, 
        data=request.data, 
        partial=True,
        context={'request': request}
    )
    
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'Task updated successfully!',
            'task': serializer.data
        }, status=200)
    
    print("Validation errors:", serializer.errors)
    return Response({
        'error': 'Validation failed',
        'details': serializer.errors
    }, status=400)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_task(request, task_id):
    
    user = request.user
    
    # Checking if user is a manager
    if not user.groups.filter(name='Managers').exists():
        return Response({'error': 'You do not have permission to delete tasks.'}, status=403)
    
    task = get_object_or_404(Task, pk=task_id)
    task.delete()
    return Response({'message': 'Task deleted successfully'}, status=204)



@api_view(['GET'])
@permission_classes([IsAuthenticated, IsManager])
def worker_productivity_stats(request):
    # Get all workers (users in Workers group)
    workers = User.objects.filter(
        groups__name__in=['Worker', 'Workers']
    ).annotate(
        total_tasks=Count('assigned_tasks'),  # Using the related_name
        completed_tasks=Count(
            'assigned_tasks',
            filter=Q(assigned_tasks__status='completed')
        )
    )
    
    data = []
    for worker in workers:
        total = worker.total_tasks
        completed = worker.completed_tasks
        
        data.append({
            'id': worker.id,
            'username': worker.username,
            'completed_tasks': completed,
            'total_tasks': total,
            'productivity': round((completed / total * 100), 2) if total > 0 else 0
        })
    
    return Response(data)




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_project_workers(request, project_id):
    try:
        project = Project.objects.get(pk=project_id)
        serializer = ProjectWorkerSerializer(project) #serialize the project object
        return Response(serializer.data)
    except Project.DoesNotExist:
        return Response({'error': 'Project not found.'}, status=404)
    



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def view_user_tasks(request):
    """View for regular users to see their assigned tasks"""
    tasks = Task.objects.filter(assigned_to=request.user)
    serializer = TaskViewSerializer(tasks, many=True)
    return Response(serializer.data)

# views.py
from .permission import IsManager

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsManager])
def view_manager_tasks(request):
    tasks = Task.objects.all().prefetch_related('assigned_to')
    serializer = TaskViewSerializer(tasks, many=True)
    return Response(serializer.data)  



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def debug_user_info(request):
    user = request.user
    return Response({
        'username': user.username,
        'groups': [g.name for g in user.groups.all()],
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser,
        'all_permissions': list(user.get_all_permissions())
    })



@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    email = request.data.get('email')
    user = User.objects.filter(email=email).first()
    
    if user:
        subject = 'Password Reset Requested'
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Use localhost:3000 for testing
        reset_link = f"http://localhost:3000/reset-password/{uid}/{token}"
        
        message = f"Hi {user.username},\n\nYou requested a password reset. Click the link below to reset your password:\n\n{reset_link}\n\nIf you did not request this, please ignore this email."
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
            )
            return Response({'success': True, 'message': 'If the email exists, a reset link has been sent.'})
        except Exception as e:
            return Response({'success': False, 'message': f'Error sending email: {str(e)}'}, status=500)
    
    return Response({'success': True, 'message': 'If the email exists, a reset link has been sent.'})



@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_confirm(request, uidb64, token):
    try:
        # Decode the user ID from the URL
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'success': False, 'message': 'Invalid or expired token.'}, status=400)
    
    # Check if the token is valid
    if not default_token_generator.check_token(user, token):
        return Response({'success': False, 'message': 'Invalid or expired token.'}, status=400)
    
    # Get the new password from the request data
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')

    if not new_password or not confirm_password:
        return Response({'success': False, 'message': 'Both password fields are required.'}, status=400)

    if new_password != confirm_password:
        return Response({'success': False, 'message': 'Passwords do not match.'}, status=400)

    # Set the new password for the user
    user.set_password(new_password)
    user.save()

    return Response({'success': True, 'message': 'Password has been reset successfully.'})





from django.contrib.auth import get_user_model

User = get_user_model()

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsManager])
def award_points(request):
    """
    Award points to a user for completing tasks or other achievements,
    optionally linking a task or a reward to the transaction.
    """
    required_fields = ['points', 'description', 'username']
    if not all(field in request.data for field in required_fields):
        return Response(
            {'error': 'Points, description, and username are required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        points = int(request.data['points'])
        if points <= 0:
            return Response(
                {'error': 'Points must be a positive integer.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = get_object_or_404(User, username=request.data['username'])
        task_id = request.data.get('task_id')
        reward_id = request.data.get('reward_id')

        with transaction.atomic():
            # 1) Update or create the UserPoints record
            user_points, _ = UserPoints.objects.get_or_create(user=user)
            user_points.total_points += points
            user_points.available_points += points
            user_points.save()

          
            tx_data = {
                'user': user,
                'transaction_type': 'earn',
                'points': points,
                'description': request.data['description'],
            }
            if task_id:
                task = get_object_or_404(Task, id=task_id)
                tx_data['related_task'] = task
            if reward_id:
                reward = get_object_or_404(Reward, id=reward_id)
                tx_data['related_reward'] = reward

           
            tx = PointsTransaction.objects.create(**tx_data)

           
            serializer = PointsTransactionSerializer(tx)

           
            return Response({
                'message': 'Points awarded successfully.',
                'total_points': user_points.total_points,
                'available_points': user_points.available_points,
                'transaction': serializer.data
            }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response(
            {'error': f'An error occurred: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_points(request):
    
    points, _ = UserPoints.objects.get_or_create(user=request.user)
    serializer = UserPointsSerializer(points)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_available_rewards(request):
   
   
    rewards = Reward.objects.filter(
        is_active=True
    ).filter(
         
        Q(eligible_users=request.user)    # User-specific rewards
    ).distinct()  # Removes duplicates if any

    serializer = RewardSerializer(rewards, many=True, context={'request': request})
    return Response({
        'count': len(serializer.data),
        'rewards': serializer.data
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def redeem_reward(request):
   
    required_fields = ['reward_name']
    if not all(field in request.data for field in required_fields):
        return Response(
            {'error': 'Reward name is required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Get the reward by name (case-insensitive)
        reward = Reward.objects.filter(
            name__iexact=request.data['reward_name'],
            is_active=True
        ).first()

        if not reward:
            return Response(
                {'error': 'No active reward found with this name.'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check eligibility
        if reward.eligible_users.exists():  # If specific users are designated
            if not reward.eligible_users.filter(id=request.user.id).exists():
                return Response(
                    {'error': 'You are not eligible to redeem this reward.'},
                    status=status.HTTP_403_FORBIDDEN
                )

        user_points = UserPoints.objects.get(user=request.user)

        if user_points.available_points < reward.point_cost:
            return Response(
                {
                    'error': f'Not enough points. You need {reward.point_cost} points but only have {user_points.available_points}.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            # Deducst points
            user_points.available_points -= reward.point_cost
            user_points.redeemed_points += reward.point_cost
            user_points.save()

            # Creates transaction record with related task if the reward has one
            transaction_data = {
                'user': request.user,
                'transaction_type': 'redeem',
                'points': -reward.point_cost,
                'description': f"Redeemed: {reward.name}",
                'related_reward': reward
            }
            
            # Includes the task if the reward has one associated
            if hasattr(reward, 'task') and reward.task:
                transaction_data['related_task'] = reward.task
                
            PointsTransaction.objects.create(**transaction_data)

            # Process reward based on type
            reward_message = process_reward(request.user, reward)

            return Response(
                {
                    'message': f'Successfully redeemed {reward.name}',
                    'remaining_points': user_points.available_points,
                    'reward_details': reward_message
                },
                status=status.HTTP_200_OK
            )

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

def process_reward(user, reward):
   
    if reward.reward_type == 'bonus':
        # In a real implementation, you would integrate with payroll here
        return {
            'type': 'cash_bonus',
            'amount': float(reward.cash_value),
            'status': 'pending_processing',
            'message': f'Cash bonus of ${reward.cash_value} will be processed in the next payroll cycle.'
        }
    
    elif reward.reward_type == 'timeoff':
        # Add to user's time off balance
        return {
            'type': 'time_off',
            'days': reward.days_off,
            'status': 'credited',
            'message': f'{reward.days_off} day(s) of paid time off has been added to your account.'
        }
    
    elif reward.reward_type == 'other':
        return {
            'type': 'other',
            'status': 'pending_fulfillment',
            'message': 'Your reward will be processed and delivered soon.'
        }
    
    return {
        'type': 'unknown',
        'status': 'pending',
        'message': 'Reward is being processed.'
    }
    
    
    
# Creating A New Reward

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsManager])
def create_reward(request):
   
    serializer = RewardCreateSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
      
        eligible_users = serializer.validated_data.pop('eligible_users', [])
        task = serializer.validated_data.pop('task', None)
        reward = serializer.save(created_by=request.user)
        
       
        if task:
            reward.task = task
            reward.save()
        
       
        if eligible_users:
            reward.eligible_users.set(eligible_users)
        
        return Response(
            {
                'message': 'Reward created successfully',
                'reward': RewardCreateSerializer(reward).data
            },
            status=status.HTTP_201_CREATED
        )
    
    return Response(
        {
            'error': 'Invalid data',
            'details': serializer.errors
        },
        status=status.HTTP_400_BAD_REQUEST
    )





@api_view(['GET'])
@permission_classes([IsAuthenticated])
def worker_points_history(request):

    transactions = PointsTransaction.objects.filter(user=request.user).order_by('-timestamp')  
    
  
    transaction_type = request.query_params.get('type', None)
    if transaction_type:
        transactions = transactions.filter(transaction_type=transaction_type)
    
    date_from = request.query_params.get('date_from', None)
    if date_from:
        try:
            date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
            transactions = transactions.filter(timestamp__gte=date_from) 
        except ValueError:
            pass
    
    date_to = request.query_params.get('date_to', None)
    if date_to:
        try:
            date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
            transactions = transactions.filter(timestamp__lte=date_to)
        except ValueError:
            pass
    
    page = request.query_params.get('page', 1)
    page_size = request.query_params.get('page_size', 10)
    
    paginator = Paginator(transactions, page_size)
    try:
        paginated_transactions = paginator.page(page)
    except EmptyPage:
        return Response(
            {'error': 'Page not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    serializer = PointsTransactionSerializer(paginated_transactions, many=True)
    
    return Response({
        'count': paginator.count,
        'total_pages': paginator.num_pages,
        'current_page': int(page),
        'transactions': serializer.data
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsManager])
def manager_points_history(request):
   
    transactions = PointsTransaction.objects.all().order_by('-timestamp')
    
    
    user_id = request.query_params.get('user_id', None)
    if user_id:
        transactions = transactions.filter(user__id=user_id)
    
    username = request.query_params.get('username', None)
    if username:
        transactions = transactions.filter(user__username__icontains=username)
    
    
    transaction_type = request.query_params.get('type', None)
    if transaction_type:
        transactions = transactions.filter(transaction_type=transaction_type)
    
   
    date_from = request.query_params.get('date_from', None)
    if date_from:
        try:
            date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
            transactions = transactions.filter(timestamp__gte=date_from)
        except ValueError:
            pass
    
    date_to = request.query_params.get('date_to', None)
    if date_to:
        try:
            date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
            transactions = transactions.filter(timestamp__lte=date_to)
        except ValueError:
            pass
    
  
    task_id = request.query_params.get('task_id', None)
    if task_id:
        transactions = transactions.filter(related_task__id=task_id)
    
   
    reward_id = request.query_params.get('reward_id', None)
    if reward_id:
        transactions = transactions.filter(related_reward__id=reward_id)
    
   
    page = request.query_params.get('page', 1)
    page_size = request.query_params.get('page_size', 20) 
    
    paginator = Paginator(transactions, page_size)
    try:
        paginated_transactions = paginator.page(page)
    except EmptyPage:
        return Response(
            {'error': 'Page not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    serializer = PointsTransactionSerializer(paginated_transactions, many=True)
    
    return Response({
        'count': paginator.count,
        'total_pages': paginator.num_pages,
        'current_page': int(page),
        'transactions': serializer.data
    })



@api_view(['PUT'])
def update_reward(request, reward_id):
    try:
        reward = Reward.objects.get(id=reward_id)
    except Reward.DoesNotExist:
        return Response({"error": "Reward not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = RewardSerializer(reward, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsManager])
def delete_reward(request, reward_id):
    
    try:
        
        reward = Reward.objects.get(
            id=reward_id,
            created_by=request.user  
        )
        
        
        reward.delete()
        
        return Response(
            {'message': 'Reward deleted successfully'},
            status=status.HTTP_200_OK
        )
        
    except Reward.DoesNotExist:
        return Response(
            {'error': 'Reward not found or you are not authorized to delete it'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])  
def get_reward_history(request):
   
    try:
       
        transactions = PointsTransaction.objects.filter(
            user=request.user,
            transaction_type__in=['redeem', 'redeem_failed']
        ).select_related(
            'related_reward'
        ).prefetch_related(
            'related_reward__eligible_users'  
        ).order_by('-timestamp')

        if not transactions.exists():
            return Response(
                {'message': 'No redemption history found'},
                status=status.HTTP_200_OK
            )

        history = []
        for transaction in transactions:
            reward = transaction.related_reward
            history.append({
                'id': transaction.id,
                'reward': {
                    'id': reward.id if reward else None,
                    'name': reward.name if reward else 'Unknown Reward',
                    'type': reward.reward_type if reward else None,
                },
                'points': abs(transaction.points),  
                'date': transaction.timestamp,
                'status': 'success' if transaction.points < 0 else 'failed',
                'description': transaction.description
            })

        return Response({
            'count': len(history),
            'history': history
        })

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        
        
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsManager])
def get_manager_rewards(request):
  
    try:
       
        rewards = Reward.objects.filter(
            created_by=request.user
        ).prefetch_related(
            'eligible_users'
        ).order_by('-created_at')

        if not rewards.exists():
            return Response(
                {'message': 'No rewards created yet'},
                status=status.HTTP_200_OK
            )

       
        reward_data = []
        for reward in rewards:
            eligible_users = reward.eligible_users.all()
            reward_data.append({
                'id': reward.id,
                'name': reward.name,
                'description': reward.description,
                'point_cost': reward.point_cost,
                'reward_type': reward.reward_type,
                'cash_value': str(reward.cash_value) if reward.cash_value else None,
                'days_off': reward.days_off,
                'is_active': reward.is_active,
                'created_at': reward.created_at,
                'created_by': reward.created_by.username,
                'eligible_users': [
                    {
                        'id': user.id,
                        'username': user.username,
                        'full_name': f"{user.first_name} {user.last_name}"
                    } for user in eligible_users
                ],
                'total_redemptions': PointsTransaction.objects.filter(
                    related_reward=reward,
                    transaction_type='redeem'
                ).count()
            })

        return Response({
            'count': len(reward_data),
            'rewards': reward_data
        })

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        
        
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_worker_rewards(request):
  
    try:
        
        points, _ = UserPoints.objects.get_or_create(user=request.user)
        points_serializer = UserPointsSerializer(points)
        
       
        available_rewards = Reward.objects.filter(
            is_active=True
        ).filter(
            Q(eligible_users__isnull=True) |  
            Q(eligible_users=request.user)    
        ).distinct()
        
        rewards_serializer = RewardSerializer(available_rewards, many=True, context={'request': request})
        
       
        transactions = PointsTransaction.objects.filter(
            user=request.user,
            transaction_type__in=['redeem', 'redeem_failed']
        ).select_related('related_reward').order_by('-timestamp')[:10] 
        
        history = []
        for transaction in transactions:
            reward = transaction.related_reward
            history.append({
                'id': transaction.id,
                'reward': {
                    'id': reward.id if reward else None,
                    'name': reward.name if reward else 'Unknown Reward',
                    'type': reward.reward_type if reward else None,
                },
                'points': abs(transaction.points),
                'date': transaction.timestamp,
                'status': 'success' if transaction.points < 0 else 'failed',
                'description': transaction.description
            })
        
        return Response({
            'points': points_serializer.data,
            'available_rewards': {
                'count': len(rewards_serializer.data),
                'rewards': rewards_serializer.data
            },
            'redemption_history': {
                'count': len(history),
                'transactions': history
            }
        })
        
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )