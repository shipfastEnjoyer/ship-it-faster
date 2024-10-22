import config from "@/config";
import { MongoDBAdapter } from "@auth/mongodb-adapter";
import EmailProvider from "next-auth/providers/email";
import GoogleProvider from "next-auth/providers/google";
import connectMongo from "./mongo";

export const authOptions = {
  // Set any random key in .env.local
  secret: process.env.NEXTAUTH_SECRET,
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_ID,
      clientSecret: process.env.GOOGLE_SECRET,
      async profile(profile) {
        return {
          id: profile.sub,
          name: profile.given_name ? profile.given_name : profile.name,
          email: profile.email,
          image: profile.picture,
          createdAt: new Date(),
        };
      },
      // Add authorization parameters for enhanced security
      authorization: {
        params: {
          prompt: "consent",
          access_type: "offline",
          response_type: "code"
        }
      }
    }),
    
    ...(connectMongo
      ? [
          EmailProvider({
            server: process.env.EMAIL_SERVER,
            from: config.mailgun.fromNoReply,
            // Add maxAge to email links
            maxAge: 60 * 60, // 1 hour
          }),
        ]
      : []),
  ],
  
  ...(connectMongo && { adapter: MongoDBAdapter(connectMongo) }),

  // Enhanced session configuration
  session: {
    strategy: "jwt",
    // Set session maximum age (required)
    maxAge: 24 * 60 * 60, // 24 hours
    // Update session every time user makes a request (recommended)
    updateAge: 12 * 60 * 60, // 12 hours
  },

  // Enhanced JWT configuration
  jwt: {
    // Set maximum age of refresh token
    maxAge: 60 * 60 * 24 * 30, // 30 days
  },

  // Enhanced security configurations
  cookies: {
    sessionToken: {
      name: `__Secure-next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
        domain: process.env.NODE_ENV === 'production' ? `.${config.domainName}` : undefined
      }
    },
    callbackUrl: {
      name: `__Secure-next-auth.callback-url`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production'
      }
    },
    csrfToken: {
      name: `__Host-next-auth.csrf-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production'
      }
    }
  },

  callbacks: {
    // Enhanced session callback with security checks
    session: async ({ session, token }) => {
      if (session?.user) {
        session.user.id = token.sub;
        
        // Add session security timestamp
        session.timestamp = Date.now();
        
        // Add additional user security checks
        if (token.blocked) {
          throw new Error('User is blocked');
        }
      }
      return session;
    },
    
    // Add JWT callback for additional token security
    jwt: async ({ token, user, account }) => {
      if (account && user) {
        // Add initial token timestamp
        token.timestamp = Date.now();
        
        // Add authentication method
        token.authMethod = account.provider;
        
        // Store minimal user data in token
        token.userId = user.id;
      }
      return token;
    }
  },

  // Enhanced event handling for security logging
  events: {
    async signIn({ user, account, isNewUser }) {
      // Log authentication events (implement your logging solution)
      console.log(`User ${user.email} signed in via ${account.provider}`);
      if (isNewUser) {
        console.log(`New user created: ${user.email}`);
      }
    },
    async signOut({ token }) {
      console.log(`User signed out: ${token.email}`);
    },
  },

  theme: {
    brandColor: config.colors.main,
    logo: `https://${config.domainName}/logoAndName.png`,
  },
  
  // Add debug logs in development
  debug: process.env.NODE_ENV === 'development',
  
  // Additional security headers
  useSecureCookies: process.env.NODE_ENV === 'production',
  pages: {
    // Custom error page for authentication errors
    error: '/auth/error',
    // Custom sign out page
    signOut: '/auth/signout',
  },
};