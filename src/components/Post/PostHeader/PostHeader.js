import React from 'react';

import './PostHeader.css'
import PostTags from './PostTags/PostTags';
import PostMeta from './PostAuthor/PostMeta';

class PostHeader extends React.PureComponent {
    getTitleBlock() {
        if (this.props.loading) {
            return (
                <div className={'skeleton-container'}>
                    <h1 className={'bp3-skeleton title ' + this.props.className}>Lorem ipsum dolor sit amet</h1>
                </div>
            );
        }
        return <h1 className="title">{this.props.title}</h1>
    }

    render() {
        return (
            <div className={this.props.className}>
                {this.getTitleBlock()}
                <PostMeta createdTime={this.props.createdTime}
                          modifiedTime={this.props.modifiedTime}
                          author={this.props.author}
                          loading={this.props.loading}
                />
                <PostTags className="post-tags" tags={this.props.tags}/>
            </div>
        )
    }
}

export default PostHeader;