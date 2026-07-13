export async function onRequest(context) {
   const { request, env } = context
   const url = new URL(request.url)
   const redirectTo = url.searchParams.get("redirect_to")

   if (!redirectTo) {
      return new Response("Parameter redirect_to wajib diisi", { status: 400 })
   }

   const allowedDomains = ["api.neoxr.eu", "shop.neoxr.eu"]
   try {
      const targetUrl = new URL(redirectTo)
      if (!allowedDomains.includes(targetUrl.host)) {
         return new Response("Domain tujuan tidak diizinkan", { status: 403 })
      }
   } catch (e) {
      return new Response("URL tujuan tidak valid", { status: 400 })
   }

   const state = btoa(JSON.stringify({ redirect_to: redirectTo }))
   const clientId = env.GITHUB_CLIENT_ID
   const gatewayCallback = "https://auth.neoxr.eu/api/auth/github/callback"
   const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(gatewayCallback)}&scope=read:user%20user:email&state=${state}`

   return Response.redirect(githubAuthUrl, 302)
}