import React from 'react';
import {
    Alignment,
    Button,
    Menu,
    MenuItem,
    Navbar,
    NavbarDivider,
    NavbarGroup,
    NavbarHeading,
    Popover,
    Position
} from '@blueprintjs/core';
import NavLink from './NavLink/NavLink';
import {Auth} from '../../data/resource/auth';

class Navigation extends React.Component {
    constructor(props) {
        super();
        this.state = {
            auth: Auth
        };
    }

    render() {
        return (
            <nav>
                <Navbar>
                    <NavbarGroup align={Alignment.LEFT}>
                        <NavbarHeading>
                            Blog
                        </NavbarHeading>
                        <NavbarDivider/>
                        <NavLink to="/" icon="home" label="Home"/>
                    </NavbarGroup>
                    <NavbarGroup align={Alignment.RIGHT}>
                        {this.state.auth.isLoggedIn() ? (
                            <div>
                                <NavLink to="/posts/new" icon="document" label="Create Post"/>
                                <Popover content={<Menu>
                                    <MenuItem text="Profile" icon="user"/>
                                    <MenuItem onClick={this.state.auth.logout} text="Logout" icon="log-out"/>
                                </Menu>} position={Position.BOTTOM}>
                                    <Button icon="user" text="Username should be here"/>
                                </Popover>
                            </div>
                        ) : (
                            <NavLink to="/login" icon="log-in" label="Login"/>
                        )}
                    </NavbarGroup>
                </Navbar>
            </nav>
        )
    }
}

export default Navigation;