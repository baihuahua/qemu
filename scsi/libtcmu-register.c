/*
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>

#include "libtcmu.h"
#include "libtcmu_priv.h"
#include "tcmuhandler-generated.h"

static gboolean
tcmulib_check_config(TCMUService1 *interface,
		     GDBusMethodInvocation *invocation,
		     gchar *cfgstring,
		     gpointer user_data)
{
	struct tcmulib_handler *handler = user_data;
	char *reason = NULL;
	bool ok;

	ok = handler->check_config ?
		handler->check_config(cfgstring, &reason) :
		TRUE;
	g_dbus_method_invocation_return_value(invocation,
		g_variant_new("(bs)", ok, reason ? : (ok ? "OK" : "unknown")));
	free(reason);
	return TRUE;
}

static GDBusObjectManagerServer *manager = NULL;

static void
tcmulib_reg_bus_acquired(GDBusConnection *connection,
			 const gchar *name,
			 gpointer user_data)
{
	struct tcmulib_handler *handler = user_data;
	GDBusObjectSkeleton *object;
	TCMUService1 *interface;
	char obj_name[128];

	manager = g_dbus_object_manager_server_new("/org/kernel/TCMUService1");

	snprintf(obj_name, sizeof(obj_name), "/org/kernel/TCMUService1/%s",
                 handler->subtype);
	object = g_dbus_object_skeleton_new(obj_name);
	interface = tcmuservice1_skeleton_new();

	g_dbus_object_skeleton_add_interface(object, G_DBUS_INTERFACE_SKELETON(interface));
	g_signal_connect(interface,
			 "handle-check-config",
			 G_CALLBACK(tcmulib_check_config),
			 handler); /* user_data */
	tcmuservice1_set_config_desc(interface, handler->cfg_desc);
        g_dbus_object_manager_server_export(manager, G_DBUS_OBJECT_SKELETON(object));
	g_dbus_object_manager_server_set_connection(manager, connection);

        g_object_unref(object);
}

static void
tcmulib_reg_name_acquired(GDBusConnection *connection,
			  const gchar     *name,
			  gpointer         user_data)
{
	struct tcmulib_handler *handler = user_data;

	handler->connection = connection;
}

static void
tcmulib_reg_name_lost(GDBusConnection *connection,
		      const gchar     *name,
		      gpointer         user_data)
{
	struct tcmulib_handler *handler = user_data;
	handler->connection = NULL;
}

static void tcmulib_handler_own_bus(struct tcmulib_handler *handler)
{
	g_bus_own_name(G_BUS_TYPE_SYSTEM,
		       "org.kernel.TCMUService1",
		       G_BUS_NAME_OWNER_FLAGS_NONE,
		       tcmulib_reg_bus_acquired,
		       tcmulib_reg_name_acquired,
		       tcmulib_reg_name_lost,
		       handler, NULL);
}

void tcmulib_register(struct tcmulib_context *ctx)
{
	struct tcmulib_handler *handler;

	/* Start acquiring buses for each subtype owned by this context. */
	darray_foreach(handler, ctx->handlers) {
		tcmulib_handler_own_bus(handler);
	}
}
