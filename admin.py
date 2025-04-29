from django.contrib import admin
from .models import Dashboard, UserProfile, TimeLog, ManagerProfile, Task, Project, PointsTransaction, Reward,UserPoints
from django.utils.timezone import localtime


# Register Dashboard and UserProfile
admin.site.register(Dashboard)
admin.site.register(UserProfile)
admin.site.register(ManagerProfile)


@admin.register(UserPoints)
class UserPointsAdmin(admin.ModelAdmin):
    list_display = ('user', 'total_points', 'available_points', 'redeemed_points')
    search_fields = ('user__username',)


@admin.register(Reward)
class RewardAdmin(admin.ModelAdmin):
    list_display = ('name', 'point_cost', 'reward_type', 'is_active')
    list_filter = ('reward_type', 'is_active')

admin.site.register(PointsTransaction)






from .models import Task

from django.contrib import admin
from django.utils.html import format_html


class TaskAdmin(admin.ModelAdmin):
    list_display = [
        'task_title',
        'project_display',
        'status_with_timestamp',  # Custom method to show status with change time
        'assigned_to_display',
        'assigned_by_username',
        'estimated_completion_datetime',
        'assigned_shift',
        'created_at',
        'updated_at',
    ]
    search_fields = [
        'task_title',
        'project__name',
        'assigned_to__username',
        'assigned_by__username'
    ]
    list_filter = [
        'assigned_shift',
        'status',
        ('created_at', admin.DateFieldListFilter),
        ('updated_at', admin.DateFieldListFilter),
    ]
    readonly_fields = [
        'created_at',
        'updated_at',
        'status_changed_at',
        
    ]
    
    # Add fields to the default ordering (newest first)
    ordering = ['-created_at']
    
    # Fields to show in the detail/edit view
    fieldsets = (
        (None, {
            'fields': ('task_title', 'description', 'status', 'project')
        }),
        ('Timing Information', {
            'fields': (
                'estimated_completion_datetime',
                'assigned_shift',
                ('created_at', 'updated_at', 'status_changed_at')
            )
        }),
        ('Assignment Information', {
            'fields': (
                'assigned_to',
                'assigned_by',
                'min_clock_cycles'
            )
        }),
        
    )

    def assigned_by_username(self, obj):
        return obj.assigned_by.username if obj.assigned_by else "N/A"
    assigned_by_username.admin_order_field = 'assigned_by'
    assigned_by_username.short_description = 'Assigned By'

    def project_display(self, obj):
        return obj.project.name if obj.project else "No Project"
    project_display.short_description = 'Project'
    project_display.admin_order_field = 'project__name'

    def assigned_to_display(self, obj):
        return ", ".join([user.username for user in obj.assigned_to.all()]) if obj.assigned_to.exists() else "N/A"
    assigned_to_display.short_description = 'Assigned To'

    def status_with_timestamp(self, obj):
        return format_html(
            "{}<br><small>{}</small>",
            obj.get_status_display(),
            obj.status_changed_at.strftime("%Y-%m-%d %H:%M") if obj.status_changed_at else "N/A"
        )
    status_with_timestamp.short_description = 'Status'
    status_with_timestamp.admin_order_field = 'status'

   

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        # Optimize by prefetching related data
        return queryset.select_related(
            'project',
            'assigned_by'
        ).prefetch_related(
            'assigned_to',
            
        )

admin.site.register(Task, TaskAdmin)


# Project Admin (add this)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at','updated_at']  # Customize as needed
    search_fields = ['name']

admin.site.register(Project, ProjectAdmin)


@admin.register(TimeLog)
class TimeLogAdmin(admin.ModelAdmin):
    # Fields to display in the list view
    list_display = ('user', 'formatted_clock_in', 'formatted_clock_out', 'duration', 'is_active')

    # Fields to filter by in the admin sidebar
    list_filter = ('user', 'clock_in', 'clock_out')

    # Fields to search for
    search_fields = ('user__username',)

    # Make certain fields readonly (e.g., clock_in and clock_out)
    readonly_fields = ('clock_in', 'clock_out', 'duration', 'is_active')

    # Display the clock-in and clock-out fields for editing
    fields = ('user', 'clock_in', 'clock_out', 'is_active', 'duration')  

    def formatted_clock_in(self, obj):
        """Display the clock-in time in a readable format."""
        if obj.clock_in:
            return localtime(obj.clock_in).strftime ('%b %d, %Y, %I:%M %p')  # Adjust format as needed
        return "N/A"
    formatted_clock_in.short_description = "Clock In"

    def formatted_clock_out(self, obj):
        """Display the clock-out time in a readable format."""
        if obj.clock_out:
            return localtime(obj.clock_out).strftime('%b %d, %Y, %I:%M %p')  # Adjust format as needed
        return "N/A"
    formatted_clock_out.short_description = "Clock Out"

    def duration(self, obj):
        """Calculate and display the duration between clock_in and clock_out."""
        if obj.clock_out and obj.clock_in:
            return obj.clock_out - obj.clock_in
        return "N/A"
    duration.short_description = "Duration"

    def is_active(self, obj):
        """Check if the user is still clocked in."""
        return obj.clock_out is None
    is_active.boolean = True  # Display as a boolean icon
    is_active.short_description = "Active"
