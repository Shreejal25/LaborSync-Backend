from django.urls import path, include
from rest_framework.routers import DefaultRouter    
from django.conf.urls.static import static
from django.conf import settings
from .views import (
    # dashboard_view,
    CustomTokenObtainPairView,
    CustomRefreshTokenView,
    logout,
    is_authenticated,
    register,
    clock_in,
    clock_out,
    user_profile_detail_view ,# Corrected import,
    register_manager,
    login_manager,
    assign_task,
    view_user_tasks,
    forgot_password,
    reset_password_confirm,
    manager_profile_view,
    manager_dashboard_view,
    user_dashboard_view,
    user_role_view,
    get_clock_history,
    get_workers, 
    add_worker,
    get_project_workers,
    create_project,
    get_projects,create_user_profile,
    update_project,
    delete_project,
    view_manager_tasks,
    debug_user_info,
    worker_productivity_stats,
    update_task,
    delete_task,
    check_task_completion,
    complete_task, 
    get_user_points,
    worker_points_history,
    manager_points_history,
    redeem_reward,
    award_points,
    get_available_rewards,
    get_reward_history,
    create_reward,
    get_manager_rewards,
    get_worker_rewards,
    delete_reward,
    update_reward,
    check_active_clock,
    get_completion_progress

)




urlpatterns = [
    
    # path('dashboard/', dashboard_view, name='dashboard'),
    path('manager-dashboard/', manager_dashboard_view, name='manager-dashboard'),
    path('user-dashboard/', user_dashboard_view, name='user-dashboard'),
    path('workers/', get_workers, name='get-workers'),  # URL for fetching workers
    path('clock-history/', get_clock_history, name='get-clock-history'), 
    path('user-role/', user_role_view, name='user-role'),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', CustomRefreshTokenView.as_view(), name='token_refresh'),
    path('logout/', logout, name='logout'),
    path('authenticated/', is_authenticated, name='is_authenticated'),
    path('register/', register, name='register'),
    path('clock_in/', clock_in, name='clock_in'),
    path('check_active_clock/', check_active_clock, name='check_active_clock'),
    path('clock_out/', clock_out, name='clock_out'),
    path('user/profile/', user_profile_detail_view, name='user_profile_detail'),  # Corrected path
    path('create-user-profile/', create_user_profile, name='create_user_profile'),
    path('manager-profile/', manager_profile_view, name='manager-profile'),
    path('register/manager/', register_manager, name='register_manager'),
    path('login/manager/', login_manager, name='login_manager'),
    path('assign/task/', assign_task, name='assign_task'),
    path('view/tasks/', view_user_tasks, name='view_user_tasks'),
    path('forgot_password/', forgot_password, name='forgot_password'),
    path('reset_password_confirm/<uidb64>/<token>/', reset_password_confirm, name='reset_password_confirm'),
    path('projects/create/', create_project, name='create_project'),
    path('projects/', get_projects, name='get_projects'),
    path('workers/add/', add_worker, name='add_worker'),  # URL for adding a worker
    path('projects/<int:project_id>/workers/', get_project_workers, name='get_project_workers'),  # Corrected line 
    path('projects/<int:project_id>/update/', update_project, name='update_project'),
    path('projects/<int:project_id>/delete/', delete_project, name='delete_project'),
    path('view/manager-tasks/', view_manager_tasks, name='manager-tasks'),
    path('debug/user-info/', debug_user_info, name='debug-user-info'),
    path('worker/productivity/stats/', worker_productivity_stats, name='worker-productivity-stats'),
    path('tasks/<int:task_id>/', update_task, name='update-task'),
    path('tasks/<int:task_id>/delete/', delete_task, name='delete-task'),
    path('tasks/<int:task_id>/check-completion/', check_task_completion, name='check-task-completion'),
    path('tasks/<int:task_id>/complete/', complete_task, name='complete-task'),
    path('points/', get_user_points, name='user-points'),
    path('points/redeem/', redeem_reward, name='redeem-points'),
    path('points/award/', award_points, name='award_points'),
    path('worker/points/', worker_points_history, name='worker_points_history'),
    path('rewards/', get_available_rewards, name='get_available_rewards'),
    path('rewards/history/', get_reward_history, name='get_reward_history'),
    path('rewards/create/', create_reward, name='create_reward'),   
    path('manager/rewards/', get_manager_rewards, name='get_manager_rewards'),
    path('worker/rewards/', get_worker_rewards, name='get_worker_rewards'),
    path('rewards/delete/<int:reward_id>/', delete_reward, name='delete-reward'),
    path ('rewards/update/<int:reward_id>/', update_reward, name ='update-reward'),
    path('manager/points/', manager_points_history, name='manager_points_history'),
    
  
         
         
    
    
    
    
]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)